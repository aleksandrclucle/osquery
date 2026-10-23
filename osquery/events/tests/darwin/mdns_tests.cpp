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

#include <gtest/gtest.h>
#include <osquery/events/darwin/mdns_parser.h>

namespace osquery {
namespace {

const std::string query =
    "[R405] DNSServiceQueryRecord START -- qname: example.com., qtype: A, "
    "flags: 0x1D000, interface index: 0, client pid: 1204 (Python), name hash: "
    "2f1e3e86";
const std::string answer =
    "[R405->Q8510] DNSServiceQueryRecord result -- event: add, expired: no, "
    "ifindex: 0, name hash: 2f1e3e86, type: A, rdata: 192.0.2.1";
mdns::Input input(const std::string& msg, int pid = 228) {
  return {msg, "2026-09-28 13:36:19.828639+0300", pid};
}

TEST(MDNSParserTests, preservesClientIdentityBoundaries) {
  for (const std::string api :
       {"DNSServiceQueryRecord", "DNSServiceGetAddrInfo"}) {
    const std::string request = "[R42] " + api + " START -- ";
    const std::string name = api == "DNSServiceQueryRecord"
                                 ? "qname: example.com., qtype: A"
                                 : "hostname: example.com., protocols: 0";
    const std::string fields =
        ", flags: 0x1D000, interface index: 0, client pid: 3500 (";
    const std::string response =
        "[R42->Q9] " + api +
        " result -- event: add, expired: no, ifindex: 0, name hash: ab, "
        "type: A, rdata: 192.0.2.1";
    for (const std::string process :
         {"client pid: 1 (",
          "client pid: 1 (spoof)",
          "worker), client pid: 1 (spoof",
          "worker), name hash: ab, client pid: 1 (spoof",
          "worker (helper), flags: 0x0, interface index: 1",
          api == "DNSServiceQueryRecord" ? "x, qtype: A" : "x, protocols: 0"}) {
      mdns::Parser parser;
      auto row = parser.parse(
          input(request + name + fields + process + "), name hash: ab"));
      ASSERT_TRUE(row && row->at("client_pid") == "3500" &&
                  row->at("client_process") == process &&
                  row->at("correlated") == "1");
      row = parser.parse(input(response));
      ASSERT_TRUE(row && row->at("client_pid") == "3500" &&
                  row->at("client_process") == process &&
                  row->at("correlated") == "1");
    }

    const std::string delimiter =
        api == "DNSServiceQueryRecord" ? ", qtype: A" : ", protocols: 0";
    for (const std::string& malformed :
         {request + name +
              ", unknown field: value, client pid: 1 (spoof), name hash: ab",
          request + name +
              ", flags: invalid, interface index: 0, client pid: 1 "
              "(spoof), name hash: ab",
          // A fake domain header must not move the real header into the
          // apparently opaque process name.
          request + name +
              ", flags: 0x0, interface index: 0, client pid: 1 (spoof" +
              delimiter + fields + "worker), name hash: ab",
          request + name + fields + "worker), name hash: ab, unknown: tail",
          request + name + fields + "worker\nspoof), name hash: ab",
          request + name + fields + "worker\rspoof), name hash: ab",
          request + name + fields + std::string(1025, 'x') + "), name hash: ab",
          request + std::string(9000, 'x'),
          request}) {
      mdns::Parser parser;
      ASSERT_TRUE(parser.parse(
          input(request + name + fields + "worker), name hash: ab")));
      // A malformed START reusing an ID must not retain the previous identity.
      auto row = parser.parse(input(malformed));
      ASSERT_FALSE(row);
      row = parser.parse(input(response));
      ASSERT_TRUE(row && row->at("correlated") == "0" &&
                  row->at("client_pid") == "-1");
    }
    mdns::Parser parser;
    auto row = parser.parse(input(request + name + ", DNSSEC enabled" + fields +
                                  "worker), name hash: ab"));
    ASSERT_TRUE(row && row->at("client_pid") == "3500");
    auto invalid_timestamp =
        input(request + name + fields + "worker), name hash: ab");
    invalid_timestamp.timestamp.assign(65, 'x');
    ASSERT_TRUE(!parser.parse(invalid_timestamp));
    row = parser.parse(input(response));
    ASSERT_TRUE(row && row->at("correlated") == "0" &&
                row->at("client_pid") == "-1");
  }
}

TEST(MDNSParserTests, supportsMulticastAndPrintedNameResults) {
  // Apple emits ->mDNS when the question has no unicast QID and periodically
  // includes the name alongside its hash instead of only the hash.
  for (const std::string api :
       {"DNSServiceQueryRecord", "DNSServiceGetAddrInfo"}) {
    const std::string name = api == "DNSServiceQueryRecord"
                                 ? "qname: example.local., qtype: A"
                                 : "hostname: example.local., protocols: 0";
    const std::string start =
        "[R42] " + api + " START -- " + name +
        ", flags: 0x0, interface index: 0, client pid: 3500 (worker), "
        "name hash: ab";
    for (const std::string target : {"Q9", "mDNS", "mDNSQ"}) {
      const std::string prefix = "[R42->" + target + "] " + api +
                                 " result -- event: add, expired: no, "
                                 "ifindex: 5, ";
      for (const std::string name_field : {"name hash: ab",
                                           "name: example.local. (ab)",
                                           "name: <private> (ab)",
                                           "name: <mask.hash: 'name'> (ab)"}) {
        mdns::Parser parser;
        ASSERT_TRUE(parser.parse(input(start)));
        auto row = parser.parse(
            input(prefix + name_field + ", type: A, rdata: 192.0.2.1"));
        ASSERT_TRUE(
            row && row->at("kind") == "answer" &&
            row->at("question_id") == (target == "Q9" ? "9" : "") &&
            row->at("interface_index") == "5" && row->at("query_type") == "A" &&
            row->at("answer") == "192.0.2.1" &&
            row->at("domain") == "example.local." &&
            row->at("client_pid") == "3500" && row->at("correlated") == "1");
        row = parser.parse(
            input(prefix + name_field + ", type: AAAA, rdata: <private>"));
        ASSERT_TRUE(row && row->at("query_type") == "AAAA" &&
                    row->at("answer") == "<private>" &&
                    row->at("redacted") == "1");
        parser.reset();
        row = parser.parse(
            input(prefix + name_field + ", type: A, rdata: 192.0.2.1"));
        ASSERT_TRUE(row && row->at("domain").empty() &&
                    row->at("client_pid") == "-1" &&
                    row->at("correlated") == "0");
      }
      for (const std::string malformed :
           {"name: forged (ab), type: A, rdata: forged.example. (ab), "
            "type: A, rdata: 192.0.2.1",
            "name: example.local. (ab), type: TXT, rdata: x, type: A, "
            "rdata: forged",
            "name: example\r.local. (ab), type: A, rdata: 192.0.2.1",
            "name: example\n.local. (ab), type: A, rdata: 192.0.2.1",
            "name: example.local. (not-hex), type: A, rdata: 192.0.2.1"}) {
        mdns::Parser parser;
        ASSERT_TRUE(parser.parse(input(start)));
        ASSERT_TRUE(!parser.parse(input(prefix + malformed)));
      }
      mdns::Parser parser;
      ASSERT_TRUE(
          !parser.parse(input(prefix + "name: " + std::string(1025, 'x') +
                              " (ab), type: A, rdata: 192.0.2.1")));
      ASSERT_TRUE(parser.parse(input(start)));
      auto txt = parser.parse(
          input(prefix + "name hash: ab, type: TXT, rdata: x, type: A"));
      ASSERT_TRUE(txt && txt->at("query_type") == "TXT" &&
                  txt->at("answer") == "x, type: A" &&
                  txt->at("client_pid") == "3500" &&
                  txt->at("correlated") == "1");
      txt = parser.parse(input(prefix + "name: example.local. (ab), type: TXT, "
                                        "rdata: x, type: A"));
      ASSERT_TRUE(txt && txt->at("query_type") == "TXT" &&
                  txt->at("answer") == "x, type: A" &&
                  txt->at("client_pid") == "3500" &&
                  txt->at("correlated") == "1");
    }
  }
}

TEST(MDNSParserTests, supportsDnssecResultMetadata) {
  for (const std::string target : {"Q9", "mDNSQ", "mDNS"}) {
    for (const std::string metadata : {"name hash: ab",
                                       "name: example.com. (ab)",
                                       "name hash: <dn:v4mDGw>"}) {
      mdns::Parser parser;
      ASSERT_TRUE(parser.parse(input(query)));
      const std::string prefix = "[R405->" + target +
                                 "] DNSServiceQueryRecord result -- event: "
                                 "add, expired: no, ifindex: 0, " +
                                 metadata;
      auto row = parser.parse(
          input(prefix + ", dnssec: secure, type: A, rdata: 192.0.2.1"));
      ASSERT_TRUE(row && row->at("answer") == "192.0.2.1" &&
                  row->at("query_type") == "A" &&
                  row->at("client_pid") == "1204");
      ASSERT_TRUE(!parser.parse(
          input(prefix + ", dnssec: , type: A, rdata: 192.0.2.1")));
      ASSERT_TRUE(!parser.parse(input(
          prefix +
          ", dnssec: secure, injected: field, type: A, rdata: 192.0.2.1")));
      ASSERT_TRUE(
          !parser.parse(input(prefix + ", dnssec: " + std::string(129, 'x') +
                              ", type: A, rdata: 192.0.2.1")));
    }
  }
}

TEST(MDNSParserTests, supportsTaggedPrivacyFormats) {
  // Synthetic fixtures reproduce the tagged hash layout observed in live logs.
  // The tags are opaque values, not decoded hashes or recoverable names.
  for (const std::string api :
       {"DNSServiceQueryRecord", "DNSServiceGetAddrInfo"}) {
    const std::string request = "[R42] " + api + " START -- ";
    const std::string label =
        api == "DNSServiceQueryRecord" ? "qname: " : "hostname: ";
    const std::string type =
        api == "DNSServiceQueryRecord" ? ", qtype: A" : ", protocols: 3";
    const std::string fields =
        ", flags: 0x1000, interface index: 0, client pid: 3500 (";
    const std::string response =
        "[R42->Q9] " + api +
        " result -- event: add, expired: no, ifindex: 0, name hash: ";
    for (const std::string tag :
         {"<dn:v4mDGw>", "<dn:j+qpcg>", "<dn:/+ABcd==>"}) {
      for (const bool masked : {false, true}) {
        mdns::Parser parser;
        const std::string domain = masked ? tag : "example.com. " + tag;
        auto row = parser.parse(input(request + label + domain + type + fields +
                                      "dns-sd), name hash: " + tag));
        ASSERT_TRUE(row && row->at("kind") == "query" &&
                    row->at("domain") == (masked ? tag : "example.com.") &&
                    row->at("client_pid") == "3500" &&
                    row->at("client_process") == "dns-sd" &&
                    row->at("redacted") == (masked ? "1" : "0"));
        ASSERT_TRUE(row->at("query_type") ==
                    (api == "DNSServiceQueryRecord" ? "A" : "A+AAAA"));
        const std::string rdata =
            masked ? "<rd:qpFUdQ>" : "192.0.2.1 <rd:qpFUdQ>";
        row =
            parser.parse(input(response + tag + ", type: A, rdata: " + rdata));
        ASSERT_TRUE(row && row->at("kind") == "answer" &&
                    row->at("answer") == (masked ? rdata : "192.0.2.1") &&
                    row->at("domain") == (masked ? tag : "example.com.") &&
                    row->at("client_pid") == "3500" &&
                    row->at("correlated") == "1" &&
                    row->at("redacted") == (masked ? "1" : "0"));
        row =
            parser.parse(input(response + tag + ", type: AAAA, rdata: <none>"));
        ASSERT_TRUE(row && row->at("kind") == "no_data" &&
                    row->at("answer") == "<none>");
        parser.parse(input("[R42] " + api + " STOP -- name hash: " + tag +
                           ", duration: 0s"));
        row = parser.parse(
            input(response + tag + ", type: A, rdata: <rd:qpFUdQ>"));
        ASSERT_TRUE(row && row->at("correlated") == "0" &&
                    row->at("client_pid") == "-1" &&
                    row->at("redacted") == "1");
      }
    }
    const std::string tag = "<dn:v4mDGw>";
    const std::string valid =
        request + label + "example.com. " + tag + type + fields;
    mdns::Parser parser;
    ASSERT_TRUE(parser.parse(input(valid + "worker), name hash: " + tag)));
    // CNAME changes the result name hash; the original request still owns
    // PID/domain.
    for (const std::string record_type : {"CNAME", "PTR", "NS", "DNAME"}) {
      auto row =
          parser.parse(input(response + "<dn:2YWpbw>, type: " + record_type +
                             ", rdata: alias.example.net. <rd:2YWpbw>"));
      ASSERT_TRUE(row && row->at("answer") == "alias.example.net." &&
                  row->at("domain") == "example.com." &&
                  row->at("client_pid") == "3500" &&
                  row->at("redacted") == "0");
    }
    auto row = parser.parse(
        input(response + tag + ", type: AAAA, rdata: 2001:db8::1 <rd:a/b+cd>"));
    ASSERT_TRUE(row && row->at("answer") == "2001:db8::1" &&
                row->at("redacted") == "0");
    row = parser.parse(input(response + tag +
                             ", type: TXT, rdata: arbitrary text <rd:qpFUdQ>"));
    ASSERT_TRUE(row && row->at("answer") == "arbitrary text <rd:qpFUdQ>" &&
                row->at("redacted") == "0");
    row = parser.parse(
        input(response + tag + ", type: A, rdata: not-an-address <rd:qpFUdQ>"));
    ASSERT_TRUE(row && row->at("answer") == "not-an-address <rd:qpFUdQ>");
    // A process name can contain PID-like text; the real header remains
    // authoritative.
    row =
        parser.parse(input(valid + "client pid: 1 (spoof), name hash: " + tag));
    ASSERT_TRUE(row && row->at("client_pid") == "3500" &&
                row->at("client_process") == "client pid: 1 (spoof");
    const std::string forged =
        request + label + "evil.example." + type +
        ", flags: 0x0, interface index: 0, client pid: 1 (fake" + type +
        fields + "worker), name hash: " + tag;
    ASSERT_TRUE(!parser.parse(input(forged)));
    row = parser.parse(
        input(response + tag + ", type: A, rdata: 192.0.2.1 <rd:qpFUdQ>"));
    ASSERT_TRUE(row && row->at("client_pid") == "-1" &&
                row->at("correlated") == "0");
    for (const std::string& invalid_hash :
         {std::string("<rd:v4mDGw>"),
          std::string("<dn:>"),
          std::string("<dn:ab cd>"),
          std::string("<dn:abc!12>"),
          "<dn:" + std::string(200, 'a') + ">"}) {
      ASSERT_TRUE(parser.parse(input(valid + "worker), name hash: " + tag)));
      ASSERT_TRUE(
          !parser.parse(input(valid + "worker), name hash: " + invalid_hash)));
      row =
          parser.parse(input(response + tag + ", type: A, rdata: <rd:qpFUdQ>"));
      ASSERT_TRUE(row && row->at("correlated") == "0" &&
                  row->at("client_pid") == "-1");
      ASSERT_TRUE(!parser.parse(
          input(response + invalid_hash + ", type: A, rdata: 192.0.2.1")));
    }
    // New hash tokens must also participate in the printed-name ambiguity
    // guard.
    ASSERT_TRUE(
        !parser.parse(input("[R42->Q9] " + api +
                            " result -- event: add, expired: no, ifindex: "
                            "0, name: forged (<dn:v4mDGw>), "
                            "type: A, rdata: forged.example. (<dn:v4mDGw>), "
                            "type: A, rdata: 192.0.2.1")));
  }
}

TEST(MDNSParserTests, correlatesAndBoundsRequests) {
  mdns::Parser p;
  const auto now = mdns::Clock::now();
  auto r = p.parse(input(query), now);
  ASSERT_TRUE(r && r->at("domain") == "example.com." &&
              r->at("client_pid") == "1204");
  r = p.parse(input(answer), now);
  ASSERT_TRUE(r && r->at("answer") == "192.0.2.1" &&
              r->at("correlated") == "1" && r->at("question_id") == "8510");
  r = p.parse(input(answer, 229), now);
  ASSERT_TRUE(r && r->at("correlated") == "0" && r->at("client_pid") == "-1");
  p.parse(input("[R405] DNSServiceQueryRecord STOP -- name hash: 2f1e3e86, "
                "duration: 0s"),
          now);
  r = p.parse(input(answer), now);
  ASSERT_TRUE(r && r->at("correlated") == "0");
  r = p.parse(input("[R7] DNSServiceGetAddrInfo START -- hostname: <private>, "
                    "protocols: 0, flags: 0x9000, interface index: 0, client "
                    "pid: 77 (Test app), name hash: aa"),
              now);
  ASSERT_TRUE(r && r->at("redacted") == "1" && r->at("query_type") == "A+AAAA");
  r = p.parse(
      input("[R7->Q8] DNSServiceGetAddrInfo result -- event: add, expired: no, "
            "ifindex: 5, name hash: aa, type: AAAA, rdata: 2001:db8::1"),
      now);
  ASSERT_TRUE(r && r->at("redacted") == "1" &&
              r->at("answer") == "2001:db8::1" &&
              r->at("client_process") == "Test app");
  r = p.parse(
      input("[R7->Q8] DNSServiceGetAddrInfo result -- event: add, expired: no, "
            "ifindex: 5, name hash: aa, type: AAAA, rdata: <none>"),
      now);
  ASSERT_TRUE(r && r->at("kind") == "no_data" && r->at("answer") == "<none>");
  r = p.parse(
      input("[R7->Q8] DNSServiceGetAddrInfo result -- event: rmv, expired: "
            "yes, ifindex: 5, name hash: aa, type: AAAA, rdata: 2001:db8::1"),
      now);
  ASSERT_TRUE(r && r->at("kind") == "remove" && r->at("expired") == "1");
  r = p.parse(input("[R9] DNSServiceQueryRecord START -- qname: <mask.hash: "
                    "'example'>, qtype: A, flags: 0x1D000, interface index: "
                    "0, client pid: 78 (Test app), name hash: bb"),
              now);
  ASSERT_TRUE(r && r->at("redacted") == "1" &&
              r->at("domain") == "<mask.hash: 'example'>");
  r = p.parse(input("[R9->Q10] DNSServiceQueryRecord result -- event: add, "
                    "expired: no, ifindex: 0, name hash: bb, type: A, "
                    "rdata: <mask.hash: 'address'>"),
              now);
  ASSERT_TRUE(r && r->at("redacted") == "1" && r->at("correlated") == "1" &&
              r->at("answer") == "<mask.hash: 'address'>");
  p.reset();
  p.max_pending = 1;
  p.parse(input(query), now);
  p.parse(input(query, 229), now + std::chrono::seconds(1));
  ASSERT_EQ(p.pending(), 1U);
  r = p.parse(input(answer), now + std::chrono::seconds(2));
  ASSERT_TRUE(r && r->at("correlated") == "0" && r->at("client_pid") == "-1");
  r = p.parse(input(answer, 229), now + std::chrono::seconds(2));
  ASSERT_TRUE(r && r->at("correlated") == "1" && r->at("client_pid") == "1204");
  r = p.parse(input(answer, 229), now + std::chrono::minutes(11));
  ASSERT_TRUE(r && r->at("correlated") == "0" && r->at("client_pid") == "-1");
  p.prune(now + std::chrono::minutes(11));
  ASSERT_TRUE(p.pending() == 0);
  r = p.parse(input("[R8] DNSServiceQueryRecord incompatible future format"),
              now);
  ASSERT_FALSE(r);
  r = p.parse(input(std::string(9000, 'x')), now);
  ASSERT_TRUE(!r);
  // Exercise reuse and steady-state bounds under many unrelated requests.
  for (int i = 0; i < 10000; ++i) {
    p.parse(input(query, i), now);
    p.parse(input(answer, i), now);
    ASSERT_TRUE(p.pending() <= 1);
  }
}

TEST(MDNSParserTests, mapsObservedFieldsToSharedSchema) {
  mdns::Parser parser;
  ASSERT_TRUE(parser.parse(input(query)));
  auto parsed = parser.parse(input(answer));
  ASSERT_TRUE(parsed);
  auto row = mdns::toDnsLookupRow(std::move(*parsed));
  EXPECT_EQ(row.at("pid"), "1204");
  EXPECT_EQ(row.at("name"), "example.com.");
  EXPECT_EQ(row.at("type"), "A");
  EXPECT_EQ(row.at("response"), "192.0.2.1");
  EXPECT_EQ(row.at("type_id"), "1");
  EXPECT_EQ(row.at("status"), "-1");
  EXPECT_TRUE(row.at("path").empty());
  EXPECT_TRUE(row.at("username").empty());
  EXPECT_EQ(row.at("datetime"), "1790591779");
  EXPECT_EQ(row.at("time_windows"), "0");
  EXPECT_EQ(row.at("timestamp"), "2026-09-28 13:36:19.828639+0300");
  EXPECT_EQ(row.at("kind"), "answer");
  EXPECT_EQ(row.at("client_process"), "Python");
  EXPECT_EQ(row.at("responder_pid"), "228");
  EXPECT_EQ(row.at("request_id"), "405");
  EXPECT_EQ(row.at("question_id"), "8510");
  EXPECT_EQ(row.at("api"), "DNSServiceQueryRecord");
  EXPECT_EQ(row.at("interface_index"), "0");
  EXPECT_EQ(row.at("expired"), "0");
  EXPECT_EQ(row.at("correlated"), "1");
  EXPECT_EQ(row.at("redacted"), "0");
  for (const auto* field :
       {"domain", "query_type", "answer", "client_pid", "time"}) {
    EXPECT_EQ(row.count(field), 0U) << field;
  }
}

TEST(MDNSParserTests, mapsResourceRecordNumbersWithoutInventingStatus) {
  const std::map<std::string, std::string> types{
      {"A", "1"},         {"AAAA", "28"},
      {"CNAME", "5"},     {"PTR", "12"},
      {"NS", "2"},        {"MX", "15"},
      {"TXT", "16"},      {"SRV", "33"},
      {"SOA", "6"},       {"DNAME", "39"},
      {"DNSKEY", "48"},   {"HTTPS", "65"},
      {"SVCB", "64"},     {"CAA", "257"},
      {"ANY", "255"},     {"TYPE65400", "65400"},
      {"65281", "65281"}, {"A+AAAA", "-1"},
      {"unknown", "-1"},  {"TYPE65536", "-1"},
      {"TYPE-1", "-1"},   {"TYPE12junk", "-1"},
      {"TYPE", "-1"}};
  for (const auto& type : types) {
    const auto row = mdns::toDnsLookupRow({{"query_type", type.first},
                                           {"kind", "no_data"},
                                           {"answer", "<none>"}});
    EXPECT_EQ(row.at("type_id"), type.second) << type.first;
    EXPECT_EQ(row.at("type"), type.first);
    EXPECT_EQ(row.at("status"), "-1");
    EXPECT_EQ(row.at("response"), "<none>");
  }
}

TEST(MDNSParserTests, convertsSourceTimestampAndRejectsInvalidCalendarValues) {
  const std::map<std::string, std::string> timestamps{
      {"2026-09-28 10:36:19.828639+0000", "1790591779"},
      {"2026-09-28 13:36:19.828639+0300", "1790591779"},
      {"2026-09-28 09:06:19.123-0130", "1790591779"},
      {"1970-01-01 00:00:01+0000", "1"},
      {"2024-02-29 00:00:00.000000+0000", "1709164800"},
      {"2025-02-29 00:00:00.000000+0000", "0"},
      {"2026-00-28 10:36:19.828639+0000", "0"},
      {"2026-09-31 10:36:19.828639+0000", "0"},
      {"2026-09-28 24:36:19.828639+0000", "0"},
      {"2026-09-28 10:60:19.828639+0000", "0"},
      {"2026-09-28 10:36:60.828639+0000", "0"},
      {"2026-09-28 10:36:19.828639+2400", "0"},
      {"2026-09-28 10:36:19.828639+0060", "0"},
      {"2026-09-28 10:36:19.828639", "0"},
      {"invalid", "0"},
      {"", "0"}};
  for (const auto& timestamp : timestamps) {
    const auto row = mdns::toDnsLookupRow({{"timestamp", timestamp.first}});
    EXPECT_EQ(row.at("datetime"), timestamp.second) << timestamp.first;
    EXPECT_EQ(row.at("timestamp"), timestamp.first);
  }
}

TEST(MDNSParserTests, resetAfterLostMessagesPreventsStaleAttribution) {
  mdns::Parser parser;
  ASSERT_TRUE(parser.parse(input(query)));
  // A lost START may have reused the request ID for a different client. The
  // publisher invalidates correlation when the source or queue reports loss.
  parser.reset();
  auto parsed = parser.parse(input(answer));
  ASSERT_TRUE(parsed);
  const auto row = mdns::toDnsLookupRow(std::move(*parsed));
  EXPECT_EQ(row.at("pid"), "-1");
  EXPECT_TRUE(row.at("name").empty());
  EXPECT_EQ(row.at("correlated"), "0");
  EXPECT_EQ(row.at("response"), "192.0.2.1");
}

} // namespace
} // namespace osquery
