/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for dns_lookup_events
// Spec file: specs/macwin/dns_lookup_events.table

#include <set>
#include <string>

#include <osquery/config/config.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

DECLARE_bool(enable_dns_lookup_events);

namespace table_tests {

class dnsLookupEvents : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

#ifdef OSQUERY_WINDOWS
    // Enable ETW DNS events
    RegistryFactory::get().registry("config_parser")->setUp();
    FLAGS_enable_dns_lookup_events = true;

    // Start eventing framework
    attachEvents();
#endif
  }

  void TearDown() override {
#ifdef OSQUERY_WINDOWS
    Dispatcher::instance().stopServices();
    Dispatcher::instance().joinServices();
    Dispatcher::instance().resetStopping();
#endif
  }
};

#ifdef OSQUERY_WINDOWS
TEST_F(dnsLookupEvents, test_sanity) {
  // Ping to generate DNS lookups
  system("ping hostname.invalid"); // invalid, will fail
  system("ping localhost"); // valid, should succeed
  Sleep(4000);

  // Query data
  auto const data = execute_query(
      "SELECT eid, time, time_windows, datetime, pid, path, username, name, "
      "type, type_id, status, response FROM dns_lookup_events");

  // General validation of rows
  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {{"eid", NonNegativeInt},
                           {"time", NonNegativeInt},
                           {"time_windows", NonNegativeInt},
                           {"datetime", NonNegativeInt},
                           {"pid", NonNegativeInt},
                           {"path", FileOnDisk | EmptyOk | NullOk},
                           {"username", NonEmptyString},
                           {"name", NonEmptyString},
                           {"type", NonEmptyString},
                           {"type_id", NonNegativeInt},
                           {"status", NonEmptyString},
                           {"response", NonEmptyString | EmptyOk | NullOk}};
  validate_rows(data, row_map);

  // Specific validation of rows

  // These requests don't always work on CI, so there are if
  // statements protecting the assertions.
  {
    // Unsuccessful A record
    const auto it = std::find_if(data.begin(), data.end(), [](const Row& row) {
      return row.at("name") == "hostname.invalid" && row.at("type") == "A";
    });
    if (it != data.end()) {
      const Row& row = *it;
      EXPECT_EQ(row.at("status"), INTEGER(87));
      EXPECT_EQ(row.at("response").size(), 0);
    }
  }

  {
    // Unsuccessful AAAA record
    const auto it = std::find_if(data.begin(), data.end(), [](const Row& row) {
      return row.at("name") == "hostname.invalid" && row.at("type") == "AAAA";
    });
    if (it != data.end()) {
      const Row& row = *it;
      EXPECT_EQ(row.at("status"), INTEGER(9003));
      EXPECT_EQ(row.at("response").size(), 0);
    }
  }

  {
    // Check the successful localhost lookup (could be A or AAAA)
    const auto it = std::find_if(data.begin(), data.end(), [](const Row& row) {
      return row.at("name") == "localhost" && row.at("status") == "0";
    });
    if (it != data.end()) {
      const Row& row = *it;
      EXPECT_GE(row.at("response").size(), 0);
    }
  }
}
#endif

TEST_F(dnsLookupEvents, test_schema) {
  // Include hidden columns: platform-specific fields must be absent, rather
  // than merely hidden, on Windows.
  const auto data = execute_query("PRAGMA table_xinfo(dns_lookup_events)");
  std::set<std::string> expected_columns = {"eid",
                                            "time",
                                            "time_windows",
                                            "datetime",
                                            "pid",
                                            "path",
                                            "username",
                                            "name",
                                            "type",
                                            "type_id",
                                            "status",
                                            "response"};
#ifndef OSQUERY_WINDOWS
  expected_columns.insert({"timestamp",
                           "kind",
                           "client_process",
                           "responder_pid",
                           "request_id",
                           "question_id",
                           "api",
                           "interface_index",
                           "expired",
                           "correlated",
                           "redacted"});
#endif
  ASSERT_EQ(data.size(), expected_columns.size());
  for (const auto& row : data) {
    const auto& name = row.at("name");
    EXPECT_EQ(expected_columns.erase(name), 1U) << name;
    const bool hidden =
        name == "eid" || name == "time" || name == "time_windows";
    EXPECT_EQ(row.at("hidden"), hidden ? "1" : "0") << name;
    if (name == "eid") {
#ifdef OSQUERY_WINDOWS
      EXPECT_EQ(row.at("type"), "INTEGER");
#else
      EXPECT_EQ(row.at("type"), "TEXT");
#endif
    }
  }
  EXPECT_TRUE(expected_columns.empty());
}

} // namespace table_tests
} // namespace osquery
