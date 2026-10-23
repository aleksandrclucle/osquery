# Native DNS lookup events on macOS

On macOS, `dns_lookup_events` records resolver events from mDNSResponder through
osquery's event framework. The collector runs inside osqueryd and uses the
standard event database and scheduled query cursors. Collector health is exposed
through `osquery_events`; no separate extension executable is required.

## Building and testing

Follow the standard [macOS build instructions](../development/building.md#macos).
Configure with `-DOSQUERY_BUILD_TESTS=ON` to include the parser, event framework
and table schema regressions in the existing CTest targets. See the
[testing instructions](../development/building.md#testing) for running them.

## Enable scheduled collection

Add these flags to the daemon's existing flag file:

```text
--disable_events=false
--enable_dns_lookup_events=true
```

The collector is disabled by default. This flag also names the existing Windows
DNS event option. Add a delivery query and a diagnostic snapshot to the daemon's
existing configuration:

```json
{
  "schedule": {
    "dns_lookup_events": {
      "query": "SELECT * FROM dns_lookup_events;",
      "interval": 30,
      "removed": false
    },
    "dns_lookup_health": {
      "query": "SELECT * FROM osquery_events WHERE name IN ('mdns', 'dns_lookup_events');",
      "interval": 60,
      "snapshot": true
    }
  }
}
```

Restart the daemon through your existing service management after updating its
configuration. Keep `events_optimize` enabled and set `events_expiry` to at least
three times the longest DNS collection interval. Keep the scheduled delivery
query unfiltered: SQL filters or `LIMIT` can discard rows after its event cursor
advances. For diagnostic history reads, use an explicit time constraint:

```sql
SELECT *, eid FROM dns_lookup_events WHERE time > 0;
```

Events and per-schedule cursors persist in the daemon's database, subject to the
normal event expiry settings. An independent osqueryi session has its own event
collector and database; it does not inspect the daemon's in-memory health.
The framework applies `events.enable_subscribers` and
`events.disable_subscribers` when registering subscribers at startup. Restart
the daemon after changing collector flags or subscriber enablement.

## Fields and migration

The existing Windows columns retain their names. On macOS, `pid`, `name`, `type`,
and `response` contain the client PID, queried domain, record type and returned
RDATA. Additional macOS fields preserve the source log's event kind, request
identifiers, original timestamp, client process name and correlation/privacy
metadata. Query `.schema dns_lookup_events` in osqueryi for the complete schema.
The hidden `eid` column is `TEXT` on macOS, preserving the event database's
zero-padded decimal identifiers exactly. Its existing Windows type remains
`INTEGER`. Treat macOS IDs as strings when comparing or deduplicating events.

| Extension field or table | Native equivalent |
|---|---|
| `dns_events` | `dns_lookup_events` |
| `client_pid`, `domain`, `query_type`, `answer` | `pid`, `name`, `type`, `response` |
| `dns_events_status` | `osquery_events.details` for the `mdns` publisher and `dns_lookup_events` subscriber |
| extension autoload entry | No longer required for this collector |

Windows response status codes have Windows-specific meanings. A macOS
`kind='no_data'` event preserves `response='<none>'` and does not by itself prove
NXDOMAIN. On macOS, `status=-1` means the source provides no Windows DNS status,
`time_windows=0`, and the unavailable `path` and `username` fields are empty.
A query row is an observed resolver API event, not necessarily a
network packet. PID `-1` means the source result could not be correlated with a
START record.

## Health in osquery_events

The publisher is `mdns`; the subscriber is `dns_lookup_events`. Existing event
framework columns such as `active`, `events` and `subscriptions` retain their
usual meaning. The optional `details` column contains a JSON object of
provider-specific metrics; providers with no details return `{}`.
For this source, publisher `events` counts published batches and subscriber
`events` counts successfully stored rows. Publisher `refreshes` counts framework
run-loop restarts; source reconnections are tracked by `details.stream_restarts`.

```sql
SELECT name, publisher, active, events, subscriptions, details
FROM osquery_events
WHERE name IN ('mdns', 'dns_lookup_events');

SELECT name,
       json_extract(details, '$.stream_running') AS stream_running,
       json_extract(details, '$.stream_queue_drops') AS queue_drops,
       json_extract(details, '$.write_errors') AS write_errors,
       json_extract(details, '$.last_error') AS last_error
FROM osquery_events
WHERE name IN ('mdns', 'dns_lookup_events');
```

`active` describes the framework lifecycle. `stream_running='1'` means the live
log source was activated; verify a fresh DNS answer to establish that data is
arriving. Counters expose source loss, queue drops, unsupported messages,
correlation evictions and storage failures. `last_error` retains the latest
recorded error after recovery. `stream_pid` is the osquery worker PID: there is no
separate `log stream` child process. Health counters reset when the process
restarts.

The former extension's `scheduled_reads` and `historical_reads` counters were
part of its RPC table adapter and are not native source metrics. Use the normal
`osquery_schedule` table to inspect scheduled query executions and performance.
The native path uses the framework's existing event database and query cursors.

The source queue holds at most 8192 messages and 16 MiB of payload. Correlation
state holds at most 4096 requests with a 600-second TTL, and writes are batched
at up to 128 events or a 500 ms flush interval. These bounds do not cap total RSS;
SQL results and other osquery components also consume memory.

## Visibility and optional logging profile

The source uses the private `OSLogEventLiveStream` interface from macOS
LoggingSupport. It reads live mDNSResponder messages for
`DNSServiceQueryRecord` and `DNSServiceGetAddrInfo`, including cached results.
It does not recover historical Unified Logs. Requests resolved in application
caches or through an application's own resolver, including encrypted DNS that
bypasses mDNSResponder, are outside its visibility. An empty table does not prove
that no DNS resolution occurred.

macOS may redact or hash domains and answers. Recognized placeholders are
preserved with `redacted=1`. For plaintext names and answers, an optional
[external DNS logging profile](https://github.com/aleksandrclucle/osquery-dns-macos/blob/main/configs/dns.mobileconfig)
configures Info logging and private-data options for `com.apple.mDNSResponder`
and `com.apple.mdns`. The profile is maintained separately and is not bundled
with or installed by osquery. Review it and deploy through System Settings or
your MDM only if readable values are required. It can persist Info logs
containing DNS activity and remains installed after osquery stops; remove it
separately when no longer needed. macOS controls whether private values are
disclosed, so the profile does not guarantee plaintext output.

Required selectors are checked at runtime, but a private API and log message
formats can change between OS releases. Check `details` for source errors and
unsupported messages, and repeat a live test on each target OS version. Offline
and schema tests do not establish live DNS visibility on a deployed machine.

## Isolated live smoke test

Run the following on a dedicated macOS test machine with live Unified Logging
access and network resolution of `example.com`:

```bash
python3 tools/tests/test_dns_lookup_events_live.py \
  --run-live --binary "$PWD/build/osquery/osqueryd" --requests 100
```

This opt-in test runs the specified osqueryd binary with extensions disabled, an
isolated configuration/database and temporary result logs. It checks disabled
flags, event registry and health, fresh correlated DNS answers, independent
schedule cursors, retained rows and fresh delivery after a restart, and bounded
shutdown. Masked values are accepted. It never changes the installed daemon,
installs a logging profile or flushes the system resolver cache. Diagnostic
state is retained under `/private/tmp` and may contain DNS activity.
Live log access depends on the OS and host policy; run with the privileges
required on your dedicated test machine.

The live test is intentionally separate from automatic CTest registration
because it requires live log access and resolver activity. Offline tests cover
parser grammars, privacy placeholders and malformed input without requiring log
access.
