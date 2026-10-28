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
#include <cstdint>
#include <mutex>

#include <boost/circular_buffer.hpp>
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
  struct Frame {
    mdns::Input input;
    std::uint64_t sequence;
    bool reset;
  };

  void processFrame(const Frame&);
  void record(const mdns::Input&);
  void flush();
  void readLoop();
  void enqueue(mdns::Input, bool reset = false);
  void sourceLoss();

  FRIEND_TEST(MDNSPublisherTests, queue_overflow_retains_newest_input);
  FRIEND_TEST(MDNSPublisherTests, queue_byte_limit_evicts_oldest);
  FRIEND_TEST(MDNSPublisherTests, oversized_input_preserves_pending_input);
  FRIEND_TEST(MDNSPublisherTests, repeated_gaps_reset_correlation);
  FRIEND_TEST(MDNSDatabaseTests, publishes_partial_and_full_batches);
  FRIEND_TEST(MDNSDatabaseTests, source_loss_preserves_delivery_order);
  FRIEND_TEST(MDNSDatabaseTests, queue_overflow_resets_before_retained_input);
  FRIEND_TEST(MDNSDatabaseTests, honors_standard_event_buffer_limit);
  FRIEND_TEST(MDNSDatabaseTests,
              persists_shared_schema_through_event_framework);
  FRIEND_TEST(MDNSDatabaseTests, dispatch_respects_publisher_shutdown);

  std::mutex queue_mutex_;
  std::condition_variable queue_ready_;
  boost::circular_buffer<Frame> queue_{8192};
  std::size_t queue_bytes_{0};
  std::uint64_t next_sequence_{0}, expected_sequence_{0};
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
