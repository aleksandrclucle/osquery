/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/darwin/mdns.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(enable_dns_lookup_events);

REGISTER(DNSLookupEventSubscriber, "event_subscriber", "dns_lookup_events");

Status DNSLookupEventSubscriber::init() {
  if (!FLAGS_enable_dns_lookup_events) {
    return Status::failure("DNS lookup events are disabled");
  }

  subscribe(&DNSLookupEventSubscriber::callback, createSubscriptionContext());
  if (numSubscriptions() == 0U) {
    return Status::failure("Cannot subscribe to the mDNS event publisher");
  }

  mdnsHealth().set("subscriber_active", 1);
  return Status::success();
}

void DNSLookupEventSubscriber::tearDown() {
  mdnsHealth().set("subscriber_active", 0);
}

Row DNSLookupEventSubscriber::getDetails() const {
  return mdnsHealth().row();
}

Status DNSLookupEventSubscriber::callback(const ECRef& ec, const SCRef&) {
  if (ec == nullptr) {
    return Status::failure("Invalid DNS event context");
  }

  std::vector<Row> rows;
  rows.reserve(ec->rows.size());
  for (const auto& row : ec->rows) {
    rows.push_back(mdns::toDnsLookupRow(row));
  }

  if (rows.empty()) {
    return Status::success();
  }

  const auto count = rows.size();
  auto status = addBatch(rows);
  if (status.ok()) {
    mdnsHealth().increment("stored_events", count);
    mdnsHealth().set("last_commit_time", getTime());
  } else {
    mdnsHealth().increment("write_errors");
    mdnsHealth().increment("write_drops", count);
    mdnsHealth().error(status.getMessage());
  }

  return status;
}

} // namespace osquery
