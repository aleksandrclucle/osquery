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

#import <Foundation/Foundation.h>
#include <atomic>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <osquery/events/darwin/mdns_log_stream.h>
#include <sys/time.h>

// Private LoggingSupport ABI, checked on macOS 26.6.2 with ObjC runtime
// introspection. Only selectors are referenced; the class is loaded at runtime.
// The same interface is used by Objective-See OverSight's LogMonitor:
// https://github.com/objective-see/OverSight/blob/main/Application/Application/LogMonitor.h
@interface MDNSLiveStreamSPI : NSObject
- (void)activate;
- (void)invalidate;
- (void)setQueue:(dispatch_queue_t)queue;
- (void)setFilterPredicate:(NSPredicate*)predicate;
- (void)setFlags:(unsigned long long)flags;
- (void)setEventHandler:(void (^)(id))callback;
- (void)setDroppedEventHandler:(void (^)(id))callback;
- (void)setInvalidationHandler:(void (^)(int, id))callback;
@end
@interface MDNSLogEventSPI : NSObject
- (NSString*)composedMessage;
- (NSString*)processImagePath;
- (int)processIdentifier;
- (unsigned long long)type;
- (const struct timeval*)unixDate;
@end

namespace osquery {
namespace mdns {
namespace {
struct StreamState {
  std::mutex mutex;
  bool enabled{false};
  std::atomic<bool> active{false};
  NativeLogStream::Callbacks callbacks;
};
std::string exceptionText(NSException* exception) {
  const char* reason = exception.reason.UTF8String;
  return reason ? std::string(reason).substr(0, 512)
                : "LoggingSupport exception";
}
} // namespace

struct NativeLogStream::Impl {
  std::shared_ptr<StreamState> state{std::make_shared<StreamState>()};
  MDNSLiveStreamSPI* __strong stream{nil};
  dispatch_queue_t queue{
      dispatch_queue_create("osquery.mdns.live", DISPATCH_QUEUE_SERIAL)};
};

NativeLogStream::NativeLogStream() : impl_(std::make_unique<Impl>()) {}
NativeLogStream::~NativeLogStream() {
  stop();
}
bool NativeLogStream::active() const {
  return impl_->state->active;
}

void NativeLogStream::stop() {
  // A callback holds this mutex while invoking the publisher. Disabling it
  // waits for in-flight delivery, and prevents access to a destroyed publisher.
  {
    std::lock_guard<std::mutex> lock(impl_->state->mutex);
    impl_->state->enabled = false;
    impl_->state->active = false;
    impl_->state->callbacks = {};
  }
  @autoreleasepool {
    @try {
      [impl_->stream invalidate];
    } @catch (NSException*) {
      // The stream is already disabled and can no longer call the publisher.
    }
    impl_->stream = nil;
  }
}

bool NativeLogStream::start(Callbacks callbacks, std::string& error) {
  stop();
  // Invalidation is asynchronous. Old stream blocks must never change the
  // state or callbacks of a newly activated subscription.
  impl_->state = std::make_shared<StreamState>();
  @autoreleasepool {
    @try {
      NSError* load_error = nil;
      if (![[NSBundle
              bundleWithPath:
                  @"/System/Library/PrivateFrameworks/LoggingSupport.framework"]
              loadAndReturnError:&load_error]) {
        error = "Cannot load LoggingSupport.framework";
        return false;
      }
      Class stream_class = NSClassFromString(@"OSLogEventLiveStream");
      Class event_class = NSClassFromString(@"OSLogEventProxy");
      for (NSString* name in @[
             @"activate",
             @"invalidate",
             @"setQueue:",
             @"setFlags:",
             @"setFilterPredicate:",
             @"setEventHandler:",
             @"setDroppedEventHandler:",
             @"setInvalidationHandler:"
           ]) {
        if (![stream_class
                instancesRespondToSelector:NSSelectorFromString(name)]) {
          error = "Unsupported LoggingSupport stream API: " +
                  std::string(name.UTF8String);
          return false;
        }
      }
      for (NSString* name in @[
             @"composedMessage",
             @"processImagePath",
             @"processIdentifier",
             @"type",
             @"unixDate"
           ]) {
        if (![event_class
                instancesRespondToSelector:NSSelectorFromString(name)]) {
          error = "Unsupported LoggingSupport event API: " +
                  std::string(name.UTF8String);
          return false;
        }
      }
      impl_->stream = [[stream_class alloc] init];
      if (!impl_->stream) {
        error = "Cannot create OSLogEventLiveStream";
        return false;
      }
      auto state = impl_->state;
      {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->callbacks = std::move(callbacks);
        state->enabled = true;
        state->active = true;
      }
      [impl_->stream setQueue:impl_->queue];
      [impl_->stream
          setFilterPredicate:
              [NSPredicate
                  predicateWithFormat:
                      @"process == 'mDNSResponder' AND (eventMessage CONTAINS "
                      @"'DNSServiceQueryRecord' OR eventMessage CONTAINS "
                      @"'DNSServiceGetAddrInfo')"]];
      // LoggingSupport live-stream level: 0=default, 1=info, 2=debug.
      [impl_->stream setFlags:1];
      [impl_->stream setEventHandler:^(id raw) {
        @autoreleasepool {
          std::lock_guard<std::mutex> lock(state->mutex);
          if (!state->enabled) {
            return;
          }
          @try {
            MDNSLogEventSPI* event = raw;
            if ([event type] != 0x0400 ||
                ![[event processImagePath]
                    isEqualToString:@"/usr/sbin/mDNSResponder"]) {
              return;
            }
            NSString* message = [event composedMessage];
            const struct timeval* tv = [event unixDate];
            if (!message || !tv || message.length > 8192) {
              state->callbacks.loss();
              return;
            }
            const char* text = message.UTF8String;
            if (!text) {
              state->callbacks.loss();
              return;
            }
            struct tm utc {};
            const time_t seconds = tv->tv_sec;
            gmtime_r(&seconds, &utc);
            char date[32], timestamp[64];
            strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &utc);
            snprintf(timestamp,
                     sizeof(timestamp),
                     "%s.%06d+0000",
                     date,
                     tv->tv_usec);
            state->callbacks.input(
                {text, timestamp, [event processIdentifier]});
          } @catch (NSException* exception) {
            state->active = false;
            state->callbacks.error(exceptionText(exception));
          }
        }
      }];
      [impl_->stream setDroppedEventHandler:^(id) {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->enabled) {
          state->callbacks.loss();
        }
      }];
      [impl_->stream setInvalidationHandler:^(int reason, id) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->active = false;
        if (state->enabled) {
          state->callbacks.error("Native log stream invalidated: " +
                                 std::to_string(reason));
        }
      }];
      [impl_->stream activate];
      return true;
    } @catch (NSException* exception) {
      error = exceptionText(exception);
      stop();
      return false;
    }
  }
}
} // namespace mdns
} // namespace osquery
