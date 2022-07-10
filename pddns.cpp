#include <iostream>
#include "dns_packet.h"
#include <unistd.h>

#include <pd/pdargs.h>

#include <boost/asio.hpp>

uint16_t get_pid()
{
  return static_cast<uint16_t>(::getpid());
}

dns_packet_t make_basic_query(const std::string& str) {
  dns_packet_t ret;
  question_t query;
  query.domain_name = encode_dns_hostname(str);
  query.type = T_A;
  query.klass = 1;
  ret.questions.push_back(std::move(query));
  ret.n_questions = 1;
  ret.id = get_pid();
  ret.header.set_qr(0);
  ret.header.set_opcode(0);
  ret.header.set_tc(0);
  ret.header.set_rd(1);
  ret.header.set_ra(0);
  ret.header.set_rcode(0);
  return ret;
}

namespace pd {

template<>
boost::asio::ip::address_v4 string_to_T(const std::string& str) {
  return boost::asio::ip::address_v4::from_string(str);
}

} // namespace pd

std::array<char, 512> get_request(const std::vector<char>& ser) {
  std::array<char, 512> ret = { 0 };
  std::memcpy(ret.data(), ser.data(), ser.size());
  return ret;
}

int main(int argc, char** argv) {
  using boost::asio::io_context;
  using boost::asio::ip::udp;
  
  pd::pdargs args(argc, argv);
  
  auto maybe_server_address = args.get<boost::asio::ip::address_v4>({"address", 'a'});
  auto hostname = args.get<std::string>({"hostname", 'h'});
  auto port = args.get_or<uint32_t>({"port", 'p'}, 53u);
  
  if (!hostname.has_value()){
    std::cout << "You have to provide hostname to lookup!\n";
    exit(1);
  }
  
  boost::asio::ip::address_v4 server_address;
  if (maybe_server_address.has_value()) {
    server_address = std::move(maybe_server_address).value();
  }
  else {
    server_address = boost::asio::ip::address_v4::from_string(read_resolv_conf()[0]); // TODO: what if multiple entries
  }
  
  io_context ioc;
  udp::socket sock(ioc);
  boost::asio::ip::udp::endpoint endpoint(server_address, port);
  sock.connect(endpoint);
  
  auto dns_request = make_basic_query(*hostname);
  auto request = get_request(dns_request.serialize_query());

  sock.send(boost::asio::buffer(request, 512));
  
  std::array<char, 512> response = { 0 };
  udp::endpoint sender_endpoint;
  size_t response_length = sock.receive_from(
      boost::asio::buffer(response, 512), sender_endpoint);
  
  auto dns_response = dns_packet_t::parse({ response.cbegin(), response.cend() });
  
  in_addr resolved_address;
  resolved_address.s_addr = dns_response.answers[0].ip;
  std::cout << inet_ntoa(resolved_address) << '\n';
  
  return 0;
}
