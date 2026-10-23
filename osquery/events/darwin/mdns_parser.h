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
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace osquery {
namespace mdns {
using Fields = std::map<std::string, std::string>;
using Clock = std::chrono::steady_clock;
struct Input {
  std::string message, timestamp;
  int responder_pid{0};
};

// Adapt the observed log fields to the shared DNS lookup schema. Unavailable
// status/type IDs are -1; datetime is zero when the source timestamp is
// invalid.
Fields toDnsLookupRow(Fields fields);

// Only client API messages are parsed. Wire-level resolver messages do not
// reliably identify the requesting process and are intentionally excluded.
class Parser {
 public:
  std::optional<Fields> parse(const Input&,
                              Clock::time_point now = Clock::now());
  void reset();
  void prune(Clock::time_point now);
  std::size_t pending() const {
    return requests_.size();
  }
  std::size_t max_pending{4096};
  std::chrono::seconds ttl{600};
  std::uint64_t unsupported{0}, uncorrelated{0}, evicted{0};

 private:
  struct Pending {
    Fields fields;
    Clock::time_point seen;
  };
  std::map<std::string, Pending> requests_;
};
} // namespace mdns
} // namespace osquery
