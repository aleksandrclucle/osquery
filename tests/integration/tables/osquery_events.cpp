/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for osquery_events
// Spec file: specs/utility/osquery_events.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/json/json.h>

namespace osquery {
namespace table_tests {

class osqueryEvents : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(osqueryEvents, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from osquery_events");
  for (const auto& row : data) {
    const auto details = row.find("details");
    ASSERT_NE(details, row.end());
    JSON doc;
    ASSERT_TRUE(doc.fromString(details->second).ok());
    ASSERT_TRUE(doc.doc().IsObject());
    for (const auto& member : doc.doc().GetObject()) {
      EXPECT_TRUE(member.value.IsString());
    }
  }
}

} // namespace table_tests
} // namespace osquery
