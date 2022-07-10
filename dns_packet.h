#ifndef PDDNS__DNS_PACKET_H_
#define PDDNS__DNS_PACKET_H_

#include <cstdint>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>

#include "utils.h"

// Types of DNS resource records
constexpr uint16_t T_A = 1;     // Ipv4 address
constexpr uint16_t T_NS = 2;    // Nameserver
constexpr uint16_t T_CNAME = 5; // canonical name
constexpr uint16_t T_SOA = 6;   // start of authority zone
constexpr uint16_t T_PTR = 12;  // domain name pointer
constexpr uint16_t T_MX = 15;   // Mail server

/**
 * -/-/-/-/-/-/-/-/-/-/-/-/   DNS HEADER (FLAGS)   -/-/-/-/-/-/-/-/-/-/-/-/-/-/
 * FIELD                          MEANING                                   SIZE
 * QR 	   Indicates if the message is a query (0) or a reply (1)              1
 * OPCODE  The type can be QUERY (standard query, 0), IQUERY
 *         (inverse query, 1), or STATUS (server status request, 2) 	       4
 * AA      Authoritative Answer, in a response, indicates if the DNS
 *         server is authoritative for the queried hostname 	               1
 * TC      TrunCation, indicates that this message was truncated
 *         due to excessive length 	                                       1
 * RD      Recursion Desired, indicates if the client means a recursive query  1
 * RA      Recursion Available, in a response, indicates if the replying
 *         DNS server supports recursion                                       1
 * Z       Zero, reserved for future use                                       3
 * RCODE 	Response code, can be NOERROR (0), FORMERR (1, Format error),
 *              SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.           4 
 */

struct dns_header_t {
  uint16_t data = 0;
  
  uint16_t qr() const noexcept {
    return (data & 0b1000000000000000) >> 15;
  }
  
  uint16_t opcode() const noexcept {
    return (data & 0b0111100000000000) >> 11;
  }
  
  uint16_t aa() const noexcept {
    return (data & 0b0000010000000000) >> 10;
  }

  uint16_t tc() const noexcept {
    return (data & 0b0000001000000000) >> 9;
  }
  
  uint16_t rd() const noexcept {
    return (data & 0b0000000100000000) >> 8;
  }

  uint16_t ra() const noexcept {
    return (data & 0b0000000010000000) >> 7;
  }
  
  uint16_t zero() const noexcept {
    return (data & 0b0000000001110000) >> 4;
  }
  
  uint16_t rcode() const noexcept {
    return (data & 0b0000000000001111);
  }
  
  void set_qr(uint16_t const val) noexcept {
    data |= val << 15; 
  }

  void set_opcode(uint16_t const val) noexcept {
    data |= val << 11;
  }

  void set_aa(uint16_t const val) noexcept {
    data |= val << 10;
  }

  void set_tc(uint16_t const val) noexcept {
    data |= val << 9;
  }

  void set_rd(uint16_t const val) noexcept {
    data |= val << 8;
  }

  void set_ra(uint16_t const val) noexcept {
    data |= val << 7;
  }

  void set_zero(uint16_t const val) noexcept {
    data |= val << 4;
  }

  void set_rcode(uint16_t const val) noexcept {
    data |= val;
  }
};

struct question_t {
  std::vector<char> domain_name;
  uint16_t type = 0;
  uint16_t klass = 0;
};

struct record_t {
  std::vector<char> domain_name;
  uint16_t type = 0;
  uint16_t klass = 0;
  uint32_t ttl = 0;
  uint16_t len = 0; 
};

struct type_a_record_t {
  record_t record;
  uint32_t ip = 0;
};

struct dns_packet_t {
  uint16_t id = 0;
  dns_header_t header;
  uint16_t n_questions = 0;
  uint16_t n_answers = 0;
  uint16_t n_authority = 0;
  uint16_t n_additional = 0;
  std::vector<question_t> questions;
  std::vector<type_a_record_t> answers;
  
  [[nodiscard]] std::vector<char> serialize_query() const {
    std::vector<char> ret;
    merge(ret, ::serialize(id));
    merge(ret, ::serialize(header.data));
    merge(ret, ::serialize(n_questions));
    merge(ret, ::serialize(n_answers));
    merge(ret, ::serialize(n_authority));
    merge(ret, ::serialize(n_additional));
    
    for(auto&& i : questions)
    {
      merge(ret, i.domain_name);
      merge(ret, ::serialize(i.type));
      merge(ret, ::serialize(i.klass));
    }
    
    return ret;
  }
  
  [[nodiscard]] static dns_packet_t parse(std::vector<char> data) {
    dns_packet_t ret;
    ret.id = extract<uint16_t>(data);
    ret.header.data = extract<uint16_t>(data);
    ret.n_questions = extract<uint16_t>(data);
    ret.n_answers = extract<uint16_t>(data);
    ret.n_authority = extract<uint16_t>(data);
    ret.n_additional = extract<uint16_t>(data);
    for (int i = 0; i != ret.n_questions; ++i) {
      question_t question;
      auto nullterm = std::find(data.cbegin(), data.cend(), char(0));
      auto sz = std::distance(data.cbegin(), nullterm);
      question.domain_name = extract(data, sz); // NOLINT: no way sz will overflow int
      question.type = extract<uint16_t>(data);
      question.klass = extract<uint16_t>(data);
      ret.questions.push_back(std::move(question));
    }
    
    for (int i = 0; i != ret.n_answers; ++i) {
      type_a_record_t answer;
      auto nullterm = std::find(data.cbegin(), data.cend(), char(0));
      auto sz = std::distance(data.cbegin(), nullterm);
      answer.record.domain_name = extract(data, sz); // NOLINT: no way sz will overflow int
      answer.record.type = extract<uint16_t>(data);
      answer.record.klass = extract<uint16_t>(data);
      answer.record.ttl = extract<uint32_t>(data);
      answer.record.len = extract<uint16_t>(data);
      answer.ip = htonl(extract<uint32_t>(data));
      ret.answers.push_back(std::move(answer));
    }
    
    return ret;
  }
};

#endif  // PDDNS__DNS_PACKET_H_
