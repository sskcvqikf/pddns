#include <iostream>
#include <iomanip>

#include <unistd.h>

#include <pd/pdargs.h>

#include <boost/asio.hpp>

#include "dns_packet.h"

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

void print_help(char* exe) {
  std::cout << "Poorly designed DNS client.\n";
  
  auto print_entry = [](std::string_view spec,
                        std::string_view desc)
  {
    std::cout << std::left << "  "
              << std::setw(26) << spec
              << desc << '\n';
  };
  std::cout << "Usage: " << exe
            << " [options] " << "--hostname <hostname>\n"
            << "Options:\n";
  print_entry("--help, -h", "show this message");
  print_entry("--hostname, -H <hostname>", "hostname to resolve");
  print_entry("--server, -s <server ip>", "server ip to query");
  print_entry("--port, -p <port>", "port of server");
}

int main(int argc, char** argv) {
  using boost::asio::io_context;
  using boost::asio::ip::udp;
  
  pd::pdargs args(argc, argv);
  
  auto is_help = args.get<bool>({"help", 'h'});
  if (is_help) {
    print_help(argv[0]);
    return 0;
  }
  
  auto maybe_server_address = args.get<boost::asio::ip::address_v4>({"server", 's'});
  auto hostname = args.get<std::string>({"hostname", 'H'});
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
