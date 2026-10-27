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

#pragma once
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <osquery/events/darwin/mdns_parser.h>
#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>

namespace osquery {
struct MDNSSubscriptionContext : SubscriptionContext {};
struct MDNSEventContext : EventContext {
  std::vector<Row> rows;
};

class MDNSEventPublisher final
    : public EventPublisher<MDNSSubscriptionContext, MDNSEventContext> {
  DECLARE_PUBLISHER("mdns")
 public:
  Status setUp() override;
  Status run() override;

 private:
  void record(const mdns::Input&);
  void flush();
  void readLoop();
  void enqueue(mdns::Input, bool reset = false);
  void sourceLoss();

  FRIEND_TEST(MDNSPublisherTests, queue_overflow_resets_correlation);
  FRIEND_TEST(MDNSPublisherTests, queue_byte_limit);
  FRIEND_TEST(MDNSPublisherTests, source_loss_resets_correlation);
  FRIEND_TEST(MDNSDatabaseTests,
              persists_shared_schema_through_event_framework);
  FRIEND_TEST(MDNSDatabaseTests, dispatch_respects_publisher_shutdown);

  struct Frame {
    mdns::Input input;
    bool reset;
  };
  std::mutex queue_mutex_;
  std::condition_variable queue_ready_;
  std::deque<Frame> queue_;
  std::size_t queue_bytes_{0};
  std::atomic<bool> reader_done_{false};
  mdns::Parser parser_;
  std::vector<Row> batch_;
  mdns::Clock::time_point last_flush_{mdns::Clock::now()}, retry_at_{},
      source_started_{};
  unsigned int backoff_{1};
};

class DNSLookupEventSubscriber final
    : public EventSubscriber<MDNSEventPublisher> {
 public:
  Status init() override;
  Status callback(const ECRef&, const SCRef&);
};

} // namespace osquery
