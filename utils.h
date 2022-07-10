#ifndef PDDNS__UTILS_H_
#define PDDNS__UTILS_H_

#include <string>
#include <cstdint>
#include <cstring>
#include <array>
#include <arpa/inet.h>
#include <fstream>
#include <sstream>

inline std::array<char, sizeof(uint16_t)> serialize(uint16_t val) {
  std::array<char, sizeof(uint16_t)> ret = { 0 };
  uint16_t nval = htons(val);
  std::memcpy(ret.data(), &nval, sizeof(uint16_t));
  return ret;
}

inline std::array<char, sizeof(uint32_t)> serialize(uint32_t val) {
  std::array<char, sizeof(uint32_t)> ret = { 0 };
  uint32_t nval = htonl(val);
  std::memcpy(ret.data(), &nval, sizeof(uint32_t));
  return ret;
}

inline std::vector<char> serialize(const std::string& str) {
  std::vector<char> ret(str.cbegin(), str.cend());
  return ret;
}

template<size_t N>
void merge(std::vector<char>& vec, const std::array<char, N>& add) {
  std::copy(add.cbegin(), add.cend(), std::back_inserter(vec));
}

inline void merge(std::vector<char>& vec, const std::vector<char>& add) {
  std::copy(add.cbegin(), add.cend(), std::back_inserter(vec));
}

template<typename Int>
Int extract(std::vector<char>& data) {
  static_assert(sizeof(Int) == -1, "Default instantiation of this template is an error.");
}

template<>
uint16_t extract<uint16_t>(std::vector<char>& data) {
  uint16_t hret = *(uint16_t*)(data.data());
  auto ret = ntohs(hret);
  data.erase(data.begin(), data.begin() + sizeof(uint16_t));
  return ret;
}

template<>
uint32_t extract<uint32_t>(std::vector<char>& data) {
  uint32_t hret = *(uint32_t*)(data.data());
  auto ret = ntohl(hret);
  data.erase(data.begin(), data.begin() + sizeof(uint32_t));
  return ret;
}

inline std::vector<char> extract(std::vector<char>& data, int n) {
  std::vector<char> ret(data.begin(), data.begin() + n);
  data.erase(data.begin(), data.begin() + n);
  return ret;
}

inline std::vector<char> encode_dns_hostname(const std::string& hostname) {
  std::stringstream ss; ss << hostname;
  std::vector<std::string> parts;
  std::string part;
  for (; std::getline(ss, part, '.'); ) {
    parts.push_back(std::move(part));
  }

  std::vector<char> ret;
  for(auto&& str : parts) {
    auto sz = str.size();
    ret.push_back(sz); // NOLINT: sz won't overflow char
    std::copy(str.cbegin(), str.cend(), std::back_inserter(ret));
  }
  ret.push_back(0);
  return ret;
}

inline std::pair<std::string, std::string> split(std::string str, const std::string& delim) {
  auto delim_pos = str.find(delim);
  std::string lhs = str.substr(0, delim_pos);
  str.erase(0, delim_pos + delim.length());
  return { std::move(lhs), std::move(str) };
}

inline std::vector<std::string> read_resolv_conf(const std::string& path = "/etc/resolv.conf") {
  std::ifstream in (path);
  if (not in.is_open()) {
    std::cerr << "Cannot open " << path << ". Exiting...";
    exit(1);
  }

  std::string line;
  std::vector<std::string> ret;
  for (; std::getline(in, line); ) {
    if (line[0] == '#')
      continue ;
    auto [name, host] = split(line, " ");
    if (name == "nameserver") {
      ret.push_back(std::move(host));
    }
  }
  return ret;
}

#endif  // PDDNS__UTILS_H_
