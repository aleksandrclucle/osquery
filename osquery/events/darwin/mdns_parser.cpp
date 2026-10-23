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

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cstdint>
#include <ctime>
#include <osquery/events/darwin/mdns_parser.h>
#include <regex>

namespace osquery {
namespace mdns {
namespace {
// The newer log formatter exposes opaque tokens instead of hexadecimal hashes.
// Bound the accepted token text; it is not an encoded value we need to decode.
const std::string token_payload = R"([A-Za-z0-9+/]{1,64}={0,2})";
const std::string domain_token = "<dn:" + token_payload + ">";
const std::string data_token = "<rd:" + token_payload + ">";
const std::string name_hash = "(?:[0-9a-fA-F]+|" + domain_token + ")";
const std::regex prefix(
    R"(^\[R([0-9]{1,10})(?:->(?:Q([0-9]{1,10})|mDNSQ?))?\] (DNSServiceQueryRecord|DNSServiceGetAddrInfo) )");
const std::regex query(
    R"(^START -- qname: ([^,\r\n]+), qtype: ([A-Za-z0-9]+)(?:, DNSSEC enabled)?, flags: 0x[0-9a-fA-F]+, interface index: -?[0-9]+, client pid: ([0-9]+) \((.*)\), name hash: ()" +
    name_hash + ")$");
const std::regex addr(
    R"(^START -- hostname: ([^,\r\n]+), protocols: ([0-9]+)(?:, DNSSEC enabled)?, flags: 0x[0-9a-fA-F]+, interface index: -?[0-9]+, client pid: ([0-9]+) \((.*)\), name hash: ()" +
    name_hash + ")$");
// A process name may contain a field delimiter. Reject it only when a second
// delimiter starts another complete header, which could have been forged in
// the unescaped domain/hostname text and would make client PID ambiguous.
const std::regex query_header_tail(
    R"(, qtype: [A-Za-z0-9]+(?:, DNSSEC enabled)?, flags: 0x[0-9a-fA-F]+, interface index: -?[0-9]+, client pid: [0-9]+ \(.*\), name hash: )" +
    name_hash + "$");
const std::regex addr_header_tail(
    R"(, protocols: [0-9]+(?:, DNSSEC enabled)?, flags: 0x[0-9a-fA-F]+, interface index: -?[0-9]+, client pid: [0-9]+ \(.*\), name hash: )" +
    name_hash + "$");
const std::regex result(
    R"(^result -- event: ([^,\r\n]+), expired: (yes|no), ifindex: (-?[0-9]+), (?:(name hash: )" +
    name_hash + R"()|name: [^,\r\n]{1,1024} \()" + name_hash +
    R"(\))(?:, dnssec: [^,\r\n]{1,128})?, type: ([^,\r\n]+), rdata: (.*)$)");
const std::regex result_header_tail(R"(, type: [^,\r\n]+, rdata: .*$)");
const std::regex private_token("^(?:" + domain_token + "|" + data_token + ")$");
const std::regex data_annotation(" " + data_token + "$");
bool redacted(const std::string& s) {
  return s.find("<private>") != std::string::npos ||
         s.find("<mask.") != std::string::npos ||
         s.find("<redacted>") != std::string::npos ||
         std::regex_match(s, private_token);
}
std::string normalizeDomain(const std::string& domain,
                            const std::string& hash) {
  const auto suffix = " " + hash;
  if (hash.compare(0, 4, "<dn:") == 0 && domain.size() > suffix.size() &&
      domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) ==
          0) {
    return domain.substr(0, domain.size() - suffix.size());
  }
  return domain;
}
bool simpleDNSName(const std::string& name) {
  if (name == ".") {
    return true;
  }
  const auto length = name.size() - (!name.empty() && name.back() == '.');
  if (length == 0 || length > 253) {
    return false;
  }
  std::size_t label_length = 0;
  for (std::size_t i = 0; i < length; ++i) {
    const auto c = name[i];
    if (c == '.') {
      if (label_length == 0) {
        return false;
      }
      label_length = 0;
    } else {
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') ||
          ++label_length > 63) {
        return false;
      }
    }
  }
  return label_length > 0;
}
std::string normalizeAnswer(const std::string& answer,
                            const std::string& type) {
  std::smatch annotation;
  if (!std::regex_search(answer, annotation, data_annotation)) {
    return answer;
  }
  const auto value = answer.substr(0, annotation.position());
  unsigned char address[sizeof(in6_addr)];
  if (((type == "A" || type == "AAAA") &&
       inet_pton(type == "A" ? AF_INET : AF_INET6, value.c_str(), address) ==
           1) ||
      ((type == "CNAME" || type == "PTR" || type == "NS" || type == "DNAME") &&
       simpleDNSName(value))) {
    return value;
  }
  // TXT, composite records and escaped names have opaque presentation text.
  return answer;
}

std::string recordTypeId(const std::string& type) {
  // DNS resource record numbers are independent of the resolver backend.
  static const std::map<std::string, std::uint16_t> record_types{
      {"A", 1},           {"NS", 2},      {"MD", 3},          {"MF", 4},
      {"CNAME", 5},       {"SOA", 6},     {"MB", 7},          {"MG", 8},
      {"MR", 9},          {"NULL", 10},   {"WKS", 11},        {"PTR", 12},
      {"HINFO", 13},      {"MINFO", 14},  {"MX", 15},         {"TXT", 16},
      {"RP", 17},         {"AFSDB", 18},  {"X25", 19},        {"ISDN", 20},
      {"RT", 21},         {"NSAP", 22},   {"NSAP-PTR", 23},   {"SIG", 24},
      {"KEY", 25},        {"PX", 26},     {"GPOS", 27},       {"AAAA", 28},
      {"LOC", 29},        {"NXT", 30},    {"EID", 31},        {"NIMLOC", 32},
      {"SRV", 33},        {"ATMA", 34},   {"NAPTR", 35},      {"KX", 36},
      {"CERT", 37},       {"A6", 38},     {"DNAME", 39},      {"SINK", 40},
      {"OPT", 41},        {"APL", 42},    {"DS", 43},         {"SSHFP", 44},
      {"IPSECKEY", 45},   {"RRSIG", 46},  {"NSEC", 47},       {"DNSKEY", 48},
      {"DHCID", 49},      {"NSEC3", 50},  {"NSEC3PARAM", 51}, {"TLSA", 52},
      {"SMIMEA", 53},     {"HIP", 55},    {"CDS", 59},        {"CDNSKEY", 60},
      {"OPENPGPKEY", 61}, {"CSYNC", 62},  {"ZONEMD", 63},     {"SVCB", 64},
      {"HTTPS", 65},      {"UINFO", 100}, {"UID", 101},       {"GID", 102},
      {"UNSPEC", 103},    {"NID", 104},   {"L32", 105},       {"L64", 106},
      {"LP", 107},        {"EUI48", 108}, {"EUI64", 109},     {"TKEY", 249},
      {"TSIG", 250},      {"IXFR", 251},  {"AXFR", 252},      {"MAILB", 253},
      {"MAILA", 254},     {"ANY", 255},   {"URI", 256},       {"CAA", 257},
      {"AVC", 258},       {"DOA", 259},   {"AMTRELAY", 260},  {"WINS", 65281},
      {"WINSR", 65282}};
  const auto entry = record_types.find(type);
  if (entry != record_types.end()) {
    return std::to_string(entry->second);
  }

  // Preserve numeric presentation of otherwise unknown record types.
  const auto offset = type.compare(0, 4, "TYPE") == 0 ? 4U : 0U;
  unsigned int value{0};
  const auto result =
      std::from_chars(type.data() + offset, type.data() + type.size(), value);
  if (result.ec == std::errc() && result.ptr == type.data() + type.size() &&
      value <= 65535U) {
    return std::to_string(value);
  }
  return "-1";
}

std::string sourceUnixTime(const std::string& timestamp) {
  // NativeLogStream emits UTC. Accept an explicit offset too, so synthetic
  // fixtures and old stored timestamps have the same interpretation.
  static const std::regex format(
      R"(^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?([+-])([0-9]{2})([0-9]{2})$)");
  std::smatch parts;
  if (timestamp.size() > 64U || !std::regex_match(timestamp, parts, format)) {
    return "0";
  }
  std::tm calendar{};
  calendar.tm_year = std::stoi(parts[1].str()) - 1900;
  calendar.tm_mon = std::stoi(parts[2].str()) - 1;
  calendar.tm_mday = std::stoi(parts[3].str());
  calendar.tm_hour = std::stoi(parts[4].str());
  calendar.tm_min = std::stoi(parts[5].str());
  calendar.tm_sec = std::stoi(parts[6].str());
  const auto expected = calendar;
  const auto epoch = timegm(&calendar);
  const auto zone_hours = std::stoi(parts[8].str());
  const auto zone_minutes = std::stoi(parts[9].str());
  if (calendar.tm_year != expected.tm_year ||
      calendar.tm_mon != expected.tm_mon ||
      calendar.tm_mday != expected.tm_mday ||
      calendar.tm_hour != expected.tm_hour ||
      calendar.tm_min != expected.tm_min ||
      calendar.tm_sec != expected.tm_sec || zone_hours > 23 ||
      zone_minutes > 59) {
    return "0";
  }
  const auto offset = (zone_hours * 60 + zone_minutes) * 60;
  return std::to_string(static_cast<std::int64_t>(epoch) -
                        (parts[7] == "+" ? offset : -offset));
}
} // namespace

Fields toDnsLookupRow(Fields fields) {
  for (const auto& names : {std::make_pair("client_pid", "pid"),
                            std::make_pair("domain", "name"),
                            std::make_pair("query_type", "type"),
                            std::make_pair("answer", "response")}) {
    auto value = fields.extract(names.first);
    if (!value.empty()) {
      value.key() = names.second;
      fields.insert(std::move(value));
    }
  }
  fields["type_id"] = recordTypeId(fields["type"]);
  fields["status"] = "-1";
  fields["path"] = "";
  fields["username"] = "";
  fields["datetime"] = sourceUnixTime(fields["timestamp"]);
  fields["time_windows"] = "0";
  return fields;
}

void Parser::reset() {
  requests_.clear();
}
void Parser::prune(Clock::time_point now) {
  for (auto it = requests_.begin(); it != requests_.end();) {
    if (now - it->second.seen > ttl) {
      it = requests_.erase(it);
    } else {
      ++it;
    }
  }
}
std::optional<Fields> Parser::parse(const Input& input, Clock::time_point now) {
  // Inspect only the bounded header first, so a rejected START can invalidate
  // stale correlation even when its body or timestamp exceeds the limits.
  std::smatch m;
  const auto header_end =
      input.message.begin() + std::min<std::size_t>(input.message.size(), 128);
  if (!std::regex_search(input.message.begin(), header_end, m, prefix)) {
    return {};
  }
  const auto api = m[3].str();
  const auto key =
      std::to_string(input.responder_pid) + ":" + m[1].str() + ":" + api;
  const auto body_offset = static_cast<std::size_t>(m.length());
  const bool is_start = input.message.compare(body_offset, 5, "START") == 0;
  if (is_start) {
    requests_.erase(key);
  }
  if (input.message.size() > 8192 || input.timestamp.size() > 64) {
    return {};
  }
  const auto body = input.message.substr(body_offset);
  if (body.find("STOP --") == 0) {
    requests_.erase(key);
    return {};
  }
  Fields row{{"timestamp", input.timestamp},
             {"request_id", m[1].str()},
             {"question_id", m[2].str()},
             {"api", api},
             {"responder_pid", std::to_string(input.responder_pid)},
             {"client_pid", "-1"},
             {"client_process", ""},
             {"domain", ""},
             {"query_type", ""},
             {"answer", ""},
             {"interface_index", "-1"},
             {"expired", "0"},
             {"correlated", "0"},
             {"redacted", "0"}};
  std::smatch start;
  if (is_start) {
    // The domain and process name are unescaped. A repeated delimiter in a
    // process name is harmless, but a second complete header is ambiguous.
    const std::string delimiter =
        api == "DNSServiceQueryRecord" ? ", qtype: " : ", protocols: ";
    const auto field = body.find(delimiter);
    if (field == std::string::npos ||
        !std::regex_match(
            body, start, api == "DNSServiceQueryRecord" ? query : addr)) {
      return {};
    }
    if (std::regex_search(body.cbegin() + field + delimiter.size(),
                          body.cend(),
                          api == "DNSServiceQueryRecord" ? query_header_tail
                                                         : addr_header_tail)) {
      return {};
    }
    row["kind"] = "query";
    row["domain"] = normalizeDomain(start[1].str(), start[5].str());
    row["client_pid"] = start[3].str();
    row["client_process"] = start[4].str();
    row["correlated"] = "1";
    row["query_type"] = api == "DNSServiceQueryRecord"
                            ? start[2].str()
                            : (start[2] == "1"   ? "A"
                               : start[2] == "2" ? "AAAA"
                                                 : "A+AAAA");
    if (start[1].length() > 1024 || row["client_process"].size() > 1024) {
      return {};
    }
    row["redacted"] = redacted(row["domain"]) ? "1" : "0";
    if (requests_.size() >= max_pending) {
      prune(now);
      if (!requests_.empty() && requests_.size() >= max_pending) {
        auto oldest = std::min_element(requests_.begin(),
                                       requests_.end(),
                                       [](const auto& a, const auto& b) {
                                         return a.second.seen < b.second.seen;
                                       });
        requests_.erase(oldest);
      }
    }
    requests_[key] = {row, now};
    return row;
  }
  std::smatch r;
  // With hash-only metadata the first type delimiter is structural. A printed
  // name is unescaped, so reject a second complete type/RDATA header while
  // preserving harmless delimiter text inside an answer.
  const std::string result_delimiter = ", type: ";
  const auto result_field = body.find(result_delimiter);
  if (result_field == std::string::npos || !std::regex_match(body, r, result) ||
      (r[1] != "add" && r[1] != "rmv" && r[1] != "remove")) {
    return {};
  }
  if (!r[4].matched &&
      std::regex_search(body.cbegin() + result_field + result_delimiter.size(),
                        body.cend(),
                        result_header_tail)) {
    return {};
  }
  row["kind"] = r[1] == "add" ? "answer" : "remove";
  row["expired"] = r[2] == "yes" ? "1" : "0";
  row["interface_index"] = r[3].str();
  row["query_type"] = r[5].str();
  if (r[6].length() > 4096) {
    return {};
  }
  row["answer"] = normalizeAnswer(r[6].str(), row["query_type"]);
  auto it = requests_.find(key);
  if (it != requests_.end() && now - it->second.seen <= ttl) {
    for (const auto* k : {"domain", "client_pid", "client_process"}) {
      row[k] = it->second.fields.at(k);
    }
    row["correlated"] = "1";
    it->second.seen = now;
  }
  // No RDATA does not uniquely identify NXDOMAIN. Keep the source marker.
  if (row["answer"] == "<none>") {
    row["kind"] = "no_data";
  }
  row["redacted"] =
      (redacted(row["domain"]) || redacted(row["answer"])) ? "1" : "0";
  return row;
}
} // namespace mdns
} // namespace osquery
