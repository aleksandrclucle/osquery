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

#include <algorithm>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/mdns.h>
#include <osquery/events/darwin/mdns_log_stream.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <thread>

namespace osquery {
FLAG(bool,
     enable_dns_lookup_events,
     false,
     "Collect mDNSResponder resolution events through the macOS live log "
     "stream");
REGISTER(MDNSEventPublisher, "event_publisher", "mdns");
namespace {
constexpr std::size_t batchSize = 128;
} // namespace

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
  if (!row) {
    return;
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
    fire(ec);
    batch_.reserve(batchSize);
  }
  last_flush_ = mdns::Clock::now();
  parser_.prune(last_flush_);
}
void MDNSEventPublisher::processFrame(const Frame& frame) {
  if (frame.sequence != expected_sequence_) {
    LOG(WARNING) << "mDNSResponder: input gap; discarded "
                 << frame.sequence - expected_sequence_
                 << " messages before the retained input";
    flush();
    parser_.reset();
  }
  expected_sequence_ = frame.sequence + 1;
  if (frame.reset) {
    flush();
    parser_.reset();
  } else {
    record(frame.input);
  }
}

void MDNSEventPublisher::enqueue(mdns::Input input, bool reset) {
  constexpr std::size_t maxQueueBytes = 16 * 1024 * 1024;
  std::lock_guard<std::mutex> lock(queue_mutex_);
  const auto sequence = next_sequence_++;
  const auto input_bytes = input.message.size() + input.timestamp.size();
  if (input_bytes > maxQueueBytes) {
    // The skipped sequence invalidates correlation before the next accepted
    // message without discarding earlier input that still fits in the queue.
    return;
  }
  while (!queue_.empty() && input_bytes > maxQueueBytes - queue_bytes_) {
    const auto& oldest = queue_.front().input;
    queue_bytes_ -= oldest.message.size() + oldest.timestamp.size();
    queue_.pop_front();
  }
  if (queue_.full()) {
    // circular_buffer replaces the oldest frame when its capacity is reached.
    const auto& oldest = queue_.front().input;
    queue_bytes_ -= oldest.message.size() + oldest.timestamp.size();
  }
  queue_.push_back({std::move(input), sequence, reset});
  queue_bytes_ += input_bytes;
  queue_ready_.notify_one();
}

void MDNSEventPublisher::sourceLoss() {
  LOG(WARNING) << "mDNSResponder: log stream reported lost input; resetting "
                  "correlation";
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
               LOG(WARNING) << "mDNSResponder: " << message;
               enqueue({}, true);
             }},
            error);
        if (started) {
          source_started_ = now;
          was_active = true;
        } else {
          LOG(WARNING) << "mDNSResponder: " << error;
          retry_at_ = now + std::chrono::seconds(backoff_);
          backoff_ = std::min(30U, backoff_ * 2);
        }
      }
    }
    pause(std::chrono::milliseconds(200));
  }
  source.stop();
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
        have_frame = true;
      } else if (reader_done_) {
        break;
      }
    }
    if (have_frame) {
      processFrame(frame);
    }
    if (mdns::Clock::now() - last_flush_ >= std::chrono::milliseconds(500)) {
      flush();
    }
  }
  reader.join();
  flush();
  return Status::success();
}

} // namespace osquery
