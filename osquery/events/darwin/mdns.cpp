/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Derived from osquery-dns-macos (Apache-2.0).
// Copyright 2026 DNS Events contributors.

#include <osquery/core/flags.h>
#include <osquery/events/darwin/mdns.h>
#include <osquery/events/darwin/mdns_log_stream.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/time.h>
#include <thread>
#include <unistd.h>

namespace osquery {
FLAG(bool,
     enable_dns_lookup_events,
     false,
     "Collect mDNSResponder resolution events through the macOS live log "
     "stream");
DECLARE_bool(disable_events);
REGISTER(MDNSEventPublisher, "event_publisher", "mdns");
DECLARE_uint64(events_expiry);
DECLARE_uint64(events_max);
namespace {
constexpr std::size_t batchSize = 128;
const std::vector<std::string> healthKeys = {
    "stream_running",       "stream_pid",           "stream_starts",
    "stream_restarts",      "stream_errors",        "received_events",
    "stored_events",        "write_errors",         "write_drops",
    "loss_notices",         "redacted_events",      "last_event_time",
    "last_commit_time",     "pending_requests",     "correlation_evictions",
    "unsupported_messages", "uncorrelated_results", "subscriber_active",
    "stream_queue_drops",   "stream_queue_bytes",   "peak_stream_queue_bytes"};
} // namespace

MDNSHealth& mdnsHealth() {
  static MDNSHealth h;
  return h;
}
void MDNSHealth::increment(const std::string& k, std::uint64_t n) {
  std::lock_guard<std::mutex> l(mutex);
  counters[k] += n;
}
void MDNSHealth::set(const std::string& k, std::uint64_t n) {
  std::lock_guard<std::mutex> l(mutex);
  counters[k] = n;
}
void MDNSHealth::error(const std::string& e) {
  std::lock_guard<std::mutex> l(mutex);
  const auto now = mdns::Clock::now();
  if (now - last_warning >= std::chrono::seconds(30)) {
    LOG(WARNING) << "mDNSResponder: " << e.substr(0, 512);
    last_warning = now;
  }
  last_error = e.substr(0, 512);
}
Row MDNSHealth::row() {
  std::lock_guard<std::mutex> l(mutex);
  Row r;
  for (const auto& k : healthKeys) {
    r[k] = std::to_string(counters[k]);
  }
  r["last_error"] = last_error;
  r["enabled"] = FLAGS_enable_dns_lookup_events ? "1" : "0";
  r["events_enabled"] = FLAGS_disable_events ? "0" : "1";
  r["events_expiry"] = std::to_string(FLAGS_events_expiry);
  r["events_max"] = std::to_string(FLAGS_events_max);
  r["framework"] = "osquery EventPublisher/EventSubscriber";
  r["stream_backend"] = "in-process OSLogEventLiveStream";
  return r;
}

Row MDNSEventPublisher::getDetails() const {
  return mdnsHealth().row();
}

Status MDNSEventPublisher::setUp() {
  if (!FLAGS_enable_dns_lookup_events) {
    return Status::failure(
        "mDNSResponder events are disabled; use --enable_dns_lookup_events");
  }
  batch_.reserve(batchSize);
  return Status::success();
}
void MDNSEventPublisher::record(const mdns::Input& input) {
  auto row = parser_.parse(input);
  mdnsHealth().set("pending_requests", parser_.pending());
  mdnsHealth().set("correlation_evictions", parser_.evicted);
  mdnsHealth().set("unsupported_messages", parser_.unsupported);
  mdnsHealth().set("uncorrelated_results", parser_.uncorrelated);
  if (!row) {
    return;
  }
  mdnsHealth().increment("received_events");
  mdnsHealth().set("last_event_time", getUnixTime());
  if (row->at("redacted") == "1") {
    mdnsHealth().increment("redacted_events");
  }
  batch_.push_back(std::move(*row));
  if (batch_.size() >= batchSize) {
    flush();
  }
}
void MDNSEventPublisher::flush() {
  if (!batch_.empty()) {
    auto ec = createEventContext();
    ec->rows.swap(batch_);
    if (isEnding()) {
      // EventFactory joins publishers before releasing subscribers. Drain
      // accepted rows while the subscriber and database are still available.
      auto sub = std::dynamic_pointer_cast<DNSLookupEventSubscriber>(
          EventFactory::getEventSubscriber("dns_lookup_events"));
      if (sub && sub->state() == EventState::EVENT_RUNNING) {
        sub->callback(ec, createSubscriptionContext());
      }
    } else {
      fire(ec);
    }
    batch_.reserve(batchSize);
  }
  last_flush_ = mdns::Clock::now();
  parser_.prune(last_flush_);
  mdnsHealth().set("pending_requests", parser_.pending());
  mdnsHealth().set("correlation_evictions", parser_.evicted);
}
void MDNSEventPublisher::enqueue(mdns::Input input, bool reset) {
  constexpr std::size_t maxQueueBytes = 16 * 1024 * 1024, maxFrames = 8192;
  std::lock_guard<std::mutex> lock(queue_mutex_);
  const auto input_bytes = input.message.size() + input.timestamp.size();
  if (queue_.size() >= maxFrames ||
      input_bytes > maxQueueBytes - queue_bytes_) {
    // A missing START or STOP makes subsequent PID/name correlation unsafe.
    // Discard pending input and serialize a reset before accepting more data.
    std::size_t drops = reset ? 0 : 1;
    for (const auto& frame : queue_) {
      drops += frame.reset ? 0 : 1;
    }
    queue_.clear();
    queue_bytes_ = 0;
    queue_.push_back({{}, true});
    mdnsHealth().increment("stream_queue_drops", drops);
    mdnsHealth().set("stream_queue_bytes", 0);
    queue_ready_.notify_one();
    return;
  }
  queue_bytes_ += input.message.size() + input.timestamp.size();
  peak_queue_bytes_ = std::max(peak_queue_bytes_, queue_bytes_);
  queue_.push_back({std::move(input), reset});
  mdnsHealth().set("stream_queue_bytes", queue_bytes_);
  mdnsHealth().set("peak_stream_queue_bytes", peak_queue_bytes_);
  queue_ready_.notify_one();
}

void MDNSEventPublisher::sourceLoss() {
  mdnsHealth().increment("loss_notices");
  enqueue({}, true);
}

void MDNSEventPublisher::readLoop() {
  mdns::NativeLogStream source;
  bool was_active = false;
  while (!isEnding()) {
    const auto now = mdns::Clock::now();
    if (!source.active()) {
      if (was_active) {
        source.stop();
        mdnsHealth().set("stream_running", 0);
        mdnsHealth().set("stream_pid", 0);
        mdnsHealth().increment("stream_restarts");
        if (now - source_started_ > std::chrono::minutes(1)) {
          backoff_ = 1;
        }
        retry_at_ = now + std::chrono::seconds(backoff_);
        backoff_ = std::min(30U, backoff_ * 2);
        was_active = false;
      }
      if (now >= retry_at_) {
        // Reset correlation before any callback from the new subscription.
        enqueue({}, true);
        std::string error;
        const bool started = source.start(
            {[this](mdns::Input input) { enqueue(std::move(input)); },
             [this] { sourceLoss(); },
             [this](const std::string& message) {
               mdnsHealth().increment("stream_errors");
               mdnsHealth().error(message);
               enqueue({}, true);
             }},
            error);
        if (started) {
          source_started_ = now;
          mdnsHealth().set("stream_running", 1);
          mdnsHealth().set("stream_pid", getpid());
          mdnsHealth().increment("stream_starts");
          was_active = true;
        } else {
          mdnsHealth().increment("stream_errors");
          mdnsHealth().error(error);
          retry_at_ = now + std::chrono::seconds(backoff_);
          backoff_ = std::min(30U, backoff_ * 2);
        }
      }
    }
    pause(std::chrono::milliseconds(200));
  }
  source.stop();
  mdnsHealth().set("stream_running", 0);
  mdnsHealth().set("stream_pid", 0);
  reader_done_ = true;
  queue_ready_.notify_one();
}

Status MDNSEventPublisher::run() {
  if (numSubscriptions() == 0U) {
    // Respect events.disable_subscribers without activating the log source.
    pause(std::chrono::seconds(1));
    return Status::success();
  }
  std::thread reader([this] { readLoop(); });
  for (;;) {
    Frame frame;
    bool have_frame = false;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_ready_.wait_for(lock, std::chrono::milliseconds(250), [this] {
        return !queue_.empty() || reader_done_.load();
      });
      if (!queue_.empty()) {
        frame = std::move(queue_.front());
        queue_.pop_front();
        queue_bytes_ -=
            frame.input.message.size() + frame.input.timestamp.size();
        mdnsHealth().set("stream_queue_bytes", queue_bytes_);
        have_frame = true;
      } else if (reader_done_) {
        break;
      }
    }
    if (have_frame) {
      if (frame.reset) {
        flush();
        parser_.reset();
      } else {
        record(frame.input);
      }
    }
    if (mdns::Clock::now() - last_flush_ >= std::chrono::milliseconds(500)) {
      flush();
    }
  }
  reader.join();
  flush();
  return Status::success();
}
void MDNSEventPublisher::tearDown() { /* run() invalidates the source and drains
                                         the queue. */
}

} // namespace osquery
