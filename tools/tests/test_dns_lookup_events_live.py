#!/usr/bin/env python3
# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

"""Opt-in native macOS DNS smoke test using only isolated daemon state.

Requires live Unified Logging access and resolution of example.com. Does not
install a profile, change the installed service, or flush the resolver cache.
Retains diagnostic files, which can contain DNS activity, in /private/tmp.
Intentionally separate from automatic CTest registration. Also verifies fresh
delivery to both schedules after restart.
"""

import argparse
import collections
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time


REGISTRY_NAMES = {"mdns", "dns_lookup_events"}


def wait_until(check, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.25)
    raise AssertionError("Timed out waiting for " + check.__name__)


def assert_healthy(health):
    assert health, "Missing DNS health snapshot"
    for key in (
        "stream_errors", "write_errors", "write_drops",
        "stream_queue_drops", "loss_notices",
    ):
        assert health[key] == "0", health
    assert health["last_error"] == "", health


class Daemon:
    def __init__(self, binary, root, enabled=True, disable_events=False):
        self.root = root
        root.mkdir()
        (root / "logs").mkdir()
        delivery = "SELECT *, eid AS event_id FROM dns_lookup_events;"
        queries = {
            "fast": {"query": delivery, "interval": 2, "removed": False},
            "slow": {"query": delivery, "interval": 5, "removed": False},
            "history": {
                "query": "SELECT *, eid AS event_id FROM dns_lookup_events WHERE time > 0;",
                "interval": 2,
                "snapshot": True,
            },
            "registry": {
                "query": "SELECT * FROM osquery_events WHERE name IN ('mdns', 'dns_lookup_events');",
                "interval": 1,
                "snapshot": True,
            },
        }
        (root / "config.json").write_text(json.dumps({"schedule": queries}))
        self.args = [
            str(binary),
            "--flagfile=/dev/null",
            "--allow_unsafe=true",
            "--disable_extensions=true",
            "--config_plugin=filesystem",
            "--logger_plugin=filesystem",
            "--enable_dns_lookup_events=" + str(enabled).lower(),
            "--disable_events=" + str(disable_events).lower(),
            "--schedule_splay_percent=0",
            "--events_expiry=3600",
            "--config_path=" + str(root / "config.json"),
            "--database_path=" + str(root / "db"),
            "--pidfile=" + str(root / "pid"),
            "--logger_path=" + str(root / "logs"),
        ]
        self.output = (root / "daemon.log").open("a")
        self.process = None
        self.shutdown_seconds = []

    def start(self):
        self.process = subprocess.Popen(
            self.args,
            stdout=self.output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def results(self):
        if self.process is not None and self.process.poll() is not None:
            raise AssertionError(
                "Daemon exited unexpectedly; inspect " + str(self.root / "daemon.log")
            )
        latest = {}
        added = collections.defaultdict(list)
        for filename in ("osqueryd.results.log", "osqueryd.snapshots.log"):
            path = self.root / "logs" / filename
            if not path.exists():
                continue
            for line in path.read_text().splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue  # The logger may still be appending the final line.
                name = record.get("name")
                if "snapshot" in record:
                    latest[name] = record["snapshot"]
                if record.get("action") == "added":
                    added[name].append(record["columns"])
                added[name].extend(record.get("diffResults", {}).get("added", []))
        return latest, added

    def health(self):
        registry = self.results()[0].get("registry", [])
        publisher = next((row for row in registry if row["name"] == "mdns"), None)
        if publisher is None:
            return None
        details = json.loads(publisher["details"])
        assert isinstance(details, dict), details
        return details

    def stop(self):
        if self.process is None:
            return
        started = time.monotonic()
        process = self.process
        self.process = None
        try:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.wait(timeout=8)

            def group_gone():
                try:
                    os.killpg(process.pid, 0)
                    return False
                except ProcessLookupError:
                    return True

            # Include the worker's lifetime, not only the watchdog parent's.
            wait_until(group_gone, timeout=3)
        except (subprocess.TimeoutExpired, AssertionError) as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise AssertionError("Daemon exceeded the shutdown budget") from error
        finally:
            self.shutdown_seconds.append(time.monotonic() - started)

    def close(self):
        try:
            self.stop()
        finally:
            self.output.close()


def warm_up(daemon):
    previous_ids = {
        row["event_id"]
        for row in daemon.results()[0].get("history", [])
    }
    resolver = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import socket, time\n"
            "for _ in range(160):\n"
            "    socket.getaddrinfo('example.com', 443)\n"
            "    time.sleep(0.25)\n",
        ],
        cwd="/private/tmp",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        def fresh_answer():
            rows = [
                row for row in daemon.results()[0].get("history", [])
                if int(row["pid"]) == resolver.pid
                and row["event_id"] not in previous_ids
            ]
            if not any(row["kind"] == "answer" for row in rows):
                return None
            assert all(row["correlated"] == "1" for row in rows), rows[:10]
            return {
                "pid": resolver.pid,
                "event_ids": {row["event_id"] for row in rows},
            }

        return wait_until(fresh_answer)
    finally:
        resolver.terminate()
        try:
            resolver.wait(timeout=3)
        except subprocess.TimeoutExpired:
            resolver.kill()
            resolver.wait(timeout=3)


def run_enabled(binary, root, requests, report):
    daemon = Daemon(binary, root / "enabled")
    try:
        daemon.start()

        def source_ready():
            health = daemon.health()
            return health if health and health["stream_running"] == "1" else None

        health = wait_until(source_ready)
        registry = daemon.results()[0]["registry"]
        assert {row["name"] for row in registry} == REGISTRY_NAMES, registry
        assert all(row["active"] == "1" for row in registry), registry
        subscriber = next(row for row in registry if row["name"] == "dns_lookup_events")
        assert subscriber["publisher"] == "mdns", subscriber
        worker = int(health["stream_pid"])
        process_listing = subprocess.check_output(
            ["/bin/ps", "-axo", "pid=,ppid=,comm="], text=True
        )
        processes = [line.split(None, 2) for line in process_listing.splitlines()]
        assert any(
            int(parts[0]) == worker and int(parts[1]) == daemon.process.pid
            for parts in processes
        ), process_listing
        assert not any(int(parts[1]) == worker for parts in processes), (
            "Native collector launched a child process", process_listing
        )
        warm_up(daemon)
        workload_start = time.monotonic()
        for _ in range(requests):
            socket.getaddrinfo("example.com", 443)
        report["resolver_seconds"] = time.monotonic() - workload_start

        def workload_delivered():
            own = [
                row for row in daemon.results()[0].get("history", [])
                if int(row["pid"]) == os.getpid()
            ]
            queries = sum(row["kind"] == "query" for row in own)
            answers = any(row["kind"] == "answer" and row["response"] for row in own)
            # A/AAAA multiplicity depends on the OS and resolver configuration.
            return own if queries >= requests and answers else None

        own = wait_until(workload_delivered)
        assert all(row["correlated"] == "1" for row in own), own[:10]
        assert all(row["response"] == "<none>" for row in own if row["kind"] == "no_data")
        ids = {row["event_id"] for row in own}

        def both_schedules_delivered():
            added = daemon.results()[1]
            return all(
                ids <= {row["event_id"] for row in added[name]}
                for name in ("fast", "slow")
            )

        wait_until(both_schedules_delivered)
        health = daemon.health()
        assert_healthy(health)
        report["workload_health"] = health
        report["registry"] = daemon.results()[0]["registry"]
        daemon.stop()
        started = time.monotonic()
        daemon.start()

        def restarted():
            health = source_ready()
            return health if health and int(health["stream_pid"]) != worker else None

        wait_until(restarted)
        report["restart_to_status_seconds"] = time.monotonic() - started
        restart_probe = warm_up(daemon)
        probe_ids = restart_probe["event_ids"]
        assert probe_ids, "The post-restart resolver probe produced no event IDs"
        assert probe_ids.isdisjoint(ids), "The post-restart probe reused retained event IDs"

        def fresh_probe_delivered_to_both_schedules():
            added = daemon.results()[1]
            return all(
                probe_ids <= {row["event_id"] for row in added[name]}
                for name in ("fast", "slow")
            )

        # A fresh source/history probe alone cannot establish delivery cursor
        # recovery. Both delivery schedules must receive its newly created IDs.
        wait_until(fresh_probe_delivered_to_both_schedules)
        time.sleep(7)  # Observe another complete slow-schedule interval.
        latest, added = daemon.results()
        assert ids <= {row["event_id"] for row in latest["history"]}, "Retained events lost"
        for name in ("fast", "slow"):
            counts = collections.Counter(row["event_id"] for row in added[name])
            assert all(counts[event_id] == 1 for event_id in ids), ("Duplicate delivery", name)
            assert all(counts[event_id] == 1 for event_id in probe_ids), (
                "Post-restart probe delivery was missing or duplicated", name,
                {event_id: counts[event_id] for event_id in sorted(probe_ids)},
            )
        final_health = daemon.health()
        assert_healthy(final_health)
        report["final_health"] = final_health
        report["post_restart_probe"] = {
            "pid": restart_probe["pid"],
            "events_checked": len(probe_ids),
            "delivery": {
                name: {
                    "received": len(probe_ids & {row["event_id"] for row in added[name]}),
                    "expected": len(probe_ids),
                    "exactly_once": True,
                }
                for name in ("fast", "slow")
            },
        }
        report.update(
            status="PASS",
            requests=requests,
            events_checked=len(ids),
            redacted_events=sum(row["redacted"] == "1" for row in own),
            checks=[
                "disabled flags", "native event registry and JSON diagnostics",
                "extensions disabled", "in-process source", "fresh correlated answers",
                "independent schedule cursors", "non-consuming history reads",
                "database and cursor persistence",
                "fresh post-restart probe delivered exactly once to both schedules",
                "bounded shutdown",
            ],
        )
    finally:
        try:
            daemon.close()
        finally:
            report["shutdown_seconds"] = daemon.shutdown_seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-live", action="store_true", help="Explicitly enable the live test")
    parser.add_argument("--binary", type=pathlib.Path, required=True, help="Path to the osqueryd binary to test")
    parser.add_argument("--requests", type=int, default=100)
    options = parser.parse_args()
    if not __debug__:
        parser.error("Run without -O or PYTHONOPTIMIZE: this test requires assertions")
    if not options.run_live:
        print("SKIP: pass --run-live to start an isolated live DNS test")
        return
    if sys.platform != "darwin" or options.requests < 1:
        parser.error("Requires macOS and a positive request count")
    binary = options.binary.resolve(strict=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix="osquery-dns-lookup-", dir="/private/tmp"))
    print("Test state: " + str(root), file=sys.stderr, flush=True)
    report = {"state": str(root), "binary": str(binary), "extensions_disabled": True}
    try:
        for name, enabled, disabled in (("flag_off", False, False), ("events_off", True, True)):
            daemon = Daemon(binary, root / name, enabled, disabled)
            try:
                daemon.start()
                health = wait_until(daemon.health)
                assert health["stream_running"] == "0" and health["stream_starts"] == "0", health
                assert health["subscriber_active"] == "0", health
                registry = daemon.results()[0].get("registry", [])
                assert {row["name"] for row in registry} == REGISTRY_NAMES, registry
                assert all(row["active"] == "0" for row in registry), registry
                report[name] = {"health": health, "registry": registry}
            finally:
                daemon.close()
        run_enabled(binary, root, options.requests, report)
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
