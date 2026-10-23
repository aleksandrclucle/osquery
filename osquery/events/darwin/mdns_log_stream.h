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
#include <functional>
#include <memory>
#include <osquery/events/darwin/mdns_parser.h>

namespace osquery {
namespace mdns {
// Live events are decoded in this process. There is no CLI helper or history
// scan. The implementation checks the private macOS API before activating it.
class NativeLogStream {
 public:
  struct Callbacks {
    std::function<void(Input)> input;
    std::function<void()> loss;
    std::function<void(const std::string&)> error;
  };
  NativeLogStream();
  ~NativeLogStream();
  bool start(Callbacks callbacks, std::string& error);
  void stop();
  bool active() const;
  NativeLogStream(const NativeLogStream&) = delete;
  NativeLogStream& operator=(const NativeLogStream&) = delete;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace mdns
} // namespace osquery
