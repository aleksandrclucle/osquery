/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/sql/row.h>
#include <osquery/database/database.h>
#include <osquery/events/darwin/mdns.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/info/tool_type.h>

namespace osquery {

DECLARE_bool(enable_dns_lookup_events);
DECLARE_bool(disable_events);

namespace {

const std::string kQuery =
    "[R405] DNSServiceQueryRecord START -- qname: example.com., qtype: A, "
    "flags: 0x1D000, interface index: 0, client pid: 1204 (Python), name hash: "
    "2f1e3e86";
const std::string kAnswer =
    "[R405->Q8510] DNSServiceQueryRecord result -- event: add, expired: no, "
    "ifindex: 0, name hash: 2f1e3e86, type: A, rdata: 192.0.2.1";

mdns::Input makeInput(const std::string& message) {
  return {message, "2026-09-28 13:36:19.828639+0000", 228};
}

} // namespace

TEST(MDNSPublisherTests, queue_overflow_resets_correlation) {
  MDNSEventPublisher publisher;
  publisher.record(makeInput(kQuery));
  ASSERT_EQ(publisher.parser_.pending(), 1U);

  const auto input = makeInput(kAnswer);
  const auto input_bytes = input.message.size() + input.timestamp.size();
  constexpr std::size_t kMaxFrames{8192U};
  for (std::size_t i = 0; i < kMaxFrames; ++i) {
    publisher.enqueue(input);
  }

  ASSERT_EQ(publisher.queue_.size(), kMaxFrames);
  EXPECT_EQ(publisher.queue_bytes_, kMaxFrames * input_bytes);
  publisher.enqueue(input);

  // Dropping any input can lose a request ID reuse or STOP. The next frame
  // consumed must invalidate correlation before another result is accepted.
  ASSERT_EQ(publisher.queue_.size(), 1U);
  EXPECT_TRUE(publisher.queue_.front().reset);
  EXPECT_TRUE(publisher.queue_.front().input.message.empty());
  EXPECT_EQ(publisher.queue_bytes_, 0U);

  publisher.enqueue(input);
  ASSERT_EQ(publisher.queue_.size(), 2U);
  EXPECT_TRUE(publisher.queue_.front().reset);
  EXPECT_FALSE(publisher.queue_.back().reset);
  EXPECT_EQ(publisher.queue_.back().input.message, kAnswer);
  EXPECT_EQ(publisher.queue_bytes_, input_bytes);
  EXPECT_FALSE(publisher.hasStarted());
}

TEST(MDNSPublisherTests, queue_byte_limit) {
  MDNSEventPublisher publisher;
  constexpr std::size_t kMaxBytes{16U * 1024U * 1024U};
  constexpr std::size_t kMessageBytes{8192U};
  const mdns::Input input{std::string(kMessageBytes, 'x'), "", 228};

  for (std::size_t i = 0; i < kMaxBytes / kMessageBytes; ++i) {
    publisher.enqueue(input);
  }
  ASSERT_EQ(publisher.queue_bytes_, kMaxBytes);

  publisher.enqueue({"x", "", 228});
  ASSERT_EQ(publisher.queue_.size(), 1U);
  EXPECT_TRUE(publisher.queue_.front().reset);
  EXPECT_EQ(publisher.queue_bytes_, 0U);

  // An individual oversized input must not bypass the aggregate byte limit.
  publisher.enqueue({std::string(kMaxBytes + 1U, 'x'), "", 228});
  ASSERT_EQ(publisher.queue_.size(), 1U);
  EXPECT_TRUE(publisher.queue_.front().reset);
  EXPECT_EQ(publisher.queue_bytes_, 0U);
}

TEST(MDNSPublisherTests, source_loss_resets_correlation) {
  MDNSEventPublisher publisher;
  publisher.record(makeInput(kQuery));
  ASSERT_EQ(publisher.parser_.pending(), 1U);
  publisher.enqueue(makeInput(kAnswer));

  const auto bytes_before = publisher.queue_bytes_;
  publisher.sourceLoss();

  ASSERT_EQ(publisher.queue_.size(), 2U);
  EXPECT_FALSE(publisher.queue_.front().reset);
  EXPECT_TRUE(publisher.queue_.back().reset);
  EXPECT_EQ(publisher.queue_bytes_, bytes_before);

  publisher.enqueue(makeInput(kAnswer));
  ASSERT_EQ(publisher.queue_.size(), 3U);
  EXPECT_TRUE(publisher.queue_[1].reset);
  EXPECT_FALSE(publisher.queue_[2].reset);
  EXPECT_EQ(publisher.queue_[2].input.message, kAnswer);
  EXPECT_FALSE(publisher.hasStarted());
}

TEST(MDNSSubscriberTests, disabled_collection_does_not_initialize_source) {
  const auto saved_enabled = FLAGS_enable_dns_lookup_events;
  FLAGS_enable_dns_lookup_events = false;
  MDNSEventPublisher publisher;
  DNSLookupEventSubscriber subscriber;
  EXPECT_FALSE(publisher.setUp().ok());
  EXPECT_FALSE(subscriber.init().ok());
  EXPECT_EQ(publisher.numSubscriptions(), 0U);
  EXPECT_FALSE(publisher.hasStarted());
  FLAGS_enable_dns_lookup_events = saved_enabled;
}

TEST(MDNSSubscriberTests, rejects_null_and_accepts_empty_context) {
  DNSLookupEventSubscriber subscriber;
  EXPECT_FALSE(subscriber.callback(nullptr, nullptr).ok());

  EXPECT_TRUE(
      subscriber.callback(MDNSEventPublisher::createEventContext(), nullptr)
          .ok());
}

class MDNSDatabaseTests : public testing::Test {
 protected:
  void SetUp() override {
    saved_enabled_ = FLAGS_enable_dns_lookup_events;
    saved_disable_events_ = FLAGS_disable_events;
    FLAGS_enable_dns_lookup_events = true;
    FLAGS_disable_events = false;
    setToolType(ToolType::TEST);
    registryAndPluginInit();
    ASSERT_TRUE(initDatabasePluginForTesting().ok());
    RegistryFactory::get().registry("config_parser")->setUp();
  }

  void TearDown() override {
    EventFactory::end(true);
    FLAGS_enable_dns_lookup_events = saved_enabled_;
    FLAGS_disable_events = saved_disable_events_;
  }

 private:
  bool saved_enabled_{false};
  bool saved_disable_events_{false};
};

TEST_F(MDNSDatabaseTests, persists_shared_schema_through_event_framework) {
  auto publisher = std::make_shared<MDNSEventPublisher>();
  ASSERT_TRUE(EventFactory::registerEventPublisher(publisher).ok());
  auto subscriber = std::make_shared<DNSLookupEventSubscriber>();
  subscriber->setName("dns_lookup_events");
  ASSERT_TRUE(EventFactory::registerEventSubscriber(subscriber).ok());
  EXPECT_EQ(subscriber->getType(), "mdns");
  EXPECT_EQ(publisher->numSubscriptions(), 1U);

  mdns::Parser parser;
  const auto request = parser.parse(makeInput(kQuery));
  const auto response = parser.parse(makeInput(kAnswer));
  ASSERT_TRUE(request);
  ASSERT_TRUE(response);
  auto context = MDNSEventPublisher::createEventContext();
  context->rows = {*request, *response};
  publisher->fire(context);
  EXPECT_EQ(publisher->numEvents(), 1U);
  EXPECT_EQ(subscriber->numEvents(), 2U);

  std::vector<std::string> keys;
  ASSERT_TRUE(
      scanDatabaseKeys(kEvents, keys, "data.mdns.dns_lookup_events.").ok());
  ASSERT_EQ(keys.size(), 2U);
  Row row;
  for (const auto& key : keys) {
    std::string serialized;
    ASSERT_TRUE(getDatabaseValue(kEvents, key, serialized).ok());
    Row stored_row;
    ASSERT_TRUE(deserializeRowJSON(serialized, stored_row).ok());
    if (stored_row.at("kind") == "answer") {
      row = std::move(stored_row);
    }
  }
  ASSERT_FALSE(row.empty());
  EXPECT_EQ(row.at("name"), "example.com.");
  EXPECT_EQ(row.at("pid"), "1204");
  EXPECT_EQ(row.at("type"), "A");
  EXPECT_EQ(row.at("type_id"), "1");
  EXPECT_EQ(row.at("response"), "192.0.2.1");
  EXPECT_EQ(row.at("status"), "-1");
  EXPECT_EQ(row.at("kind"), "answer");
  EXPECT_FALSE(row.at("eid").empty());
  EXPECT_NE(row.at("time"), "0");
  EXPECT_EQ(row.count("domain"), 0U);
  EXPECT_EQ(row.count("client_pid"), 0U);

  QueryData events;
  auto status = query(
      "SELECT publisher, events, subscriptions, active FROM osquery_events "
      "WHERE name = 'dns_lookup_events' AND type = 'subscriber'",
      events);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_EQ(events.front().at("publisher"), "mdns");
  EXPECT_EQ(events.front().at("events"), "2");
  EXPECT_EQ(events.front().at("subscriptions"), "1");
  EXPECT_EQ(events.front().at("active"), "1");

  // Registration, metadata queries, and dispatch must not start the live
  // source.
  EXPECT_FALSE(publisher->hasStarted());
}

TEST_F(MDNSDatabaseTests, dispatch_respects_publisher_shutdown) {
  auto publisher = std::make_shared<MDNSEventPublisher>();
  ASSERT_TRUE(EventFactory::registerEventPublisher(publisher).ok());
  auto subscriber = std::make_shared<DNSLookupEventSubscriber>();
  subscriber->setName("dns_lookup_events");
  ASSERT_TRUE(EventFactory::registerEventSubscriber(subscriber).ok());

  publisher->record(makeInput(kQuery));
  publisher->record(makeInput(kAnswer));
  ASSERT_EQ(publisher->batch_.size(), 2U);
  publisher->flush();
  EXPECT_EQ(publisher->numEvents(), 1U);
  EXPECT_EQ(subscriber->numEvents(), 2U);

  // Follow the framework shutdown boundary: no direct subscriber delivery
  // after EventFactory marks the publisher as ending.
  publisher->record(makeInput(kQuery));
  publisher->record(makeInput(kAnswer));
  ASSERT_EQ(publisher->batch_.size(), 2U);
  publisher->isEnding(true);
  publisher->flush();
  EXPECT_TRUE(publisher->batch_.empty());
  EXPECT_EQ(publisher->numEvents(), 1U);
  EXPECT_EQ(subscriber->numEvents(), 2U);

  std::vector<std::string> keys;
  ASSERT_TRUE(
      scanDatabaseKeys(kEvents, keys, "data.mdns.dns_lookup_events.").ok());
  EXPECT_EQ(keys.size(), 2U);
  EXPECT_FALSE(publisher->hasStarted());
}

TEST_F(MDNSDatabaseTests,
       padded_event_identifiers_remain_distinct_text_in_sql) {
  auto publisher = std::make_shared<MDNSEventPublisher>();
  ASSERT_TRUE(EventFactory::registerEventPublisher(publisher).ok());
  auto subscriber = std::make_shared<DNSLookupEventSubscriber>();
  subscriber->setName("dns_lookup_events");
  ASSERT_TRUE(EventFactory::registerEventSubscriber(subscriber).ok());

  mdns::Parser parser;
  ASSERT_TRUE(parser.parse(makeInput(kQuery)));
  const auto response = parser.parse(makeInput(kAnswer));
  ASSERT_TRUE(response);

  // Exercise IDs with decimal digits 8 and 9 and the transition to two digits.
  // INTEGER affinity interprets padded strings as octal, losing those values.
  constexpr std::size_t kRowCount{12U};
  auto context = MDNSEventPublisher::createEventContext();
  for (std::size_t i = 1U; i <= kRowCount; ++i) {
    context->rows.push_back(*response);
    context->rows.back()["answer"] = "192.0.2." + std::to_string(i);
  }
  ASSERT_TRUE(subscriber->callback(context, nullptr).ok());

  std::vector<std::string> keys;
  ASSERT_TRUE(
      scanDatabaseKeys(kEvents, keys, "data.mdns.dns_lookup_events.").ok());
  ASSERT_EQ(keys.size(), kRowCount);
  std::map<std::string, std::string> stored_responses;
  for (const auto& key : keys) {
    std::string serialized;
    ASSERT_TRUE(getDatabaseValue(kEvents, key, serialized).ok());
    Row row;
    ASSERT_TRUE(deserializeRowJSON(serialized, row).ok());
    stored_responses.emplace(row.at("eid"), row.at("response"));
  }
  ASSERT_EQ(stored_responses.size(), kRowCount);

  QueryData sql_rows;
  auto status = query(
      "SELECT eid, response, typeof(eid) AS eid_type FROM dns_lookup_events "
      "WHERE time >= 0",
      sql_rows);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(sql_rows.size(), kRowCount);
  std::set<std::string> identifiers;
  for (const auto& row : sql_rows) {
    const auto& eid = row.at("eid");
    EXPECT_FALSE(eid.empty());
    EXPECT_EQ(row.at("eid_type"), "text");
    EXPECT_TRUE(identifiers.insert(eid).second);
    const auto stored = stored_responses.find(eid);
    ASSERT_NE(stored, stored_responses.end());
    EXPECT_EQ(row.at("response"), stored->second);
  }
  EXPECT_EQ(identifiers.size(), kRowCount);

  QueryData counts;
  status = query(
      "SELECT COUNT(*) AS total, COUNT(eid) AS nonnull, "
      "COUNT(DISTINCT eid) AS distinct_ids FROM dns_lookup_events "
      "WHERE time >= 0",
      counts);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(counts.size(), 1U);
  EXPECT_EQ(counts.front().at("total"), "12");
  EXPECT_EQ(counts.front().at("nonnull"), "12");
  EXPECT_EQ(counts.front().at("distinct_ids"), "12");
  EXPECT_FALSE(publisher->hasStarted());
}

} // namespace osquery
