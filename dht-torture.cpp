/*
The MIT License (MIT)

Copyright (c) 2015 BitTorrent Inc.

author: Steven Siloti

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <functional>
#include <vector>
#include <boost/asio.hpp>
#include <boost/crc.hpp>

#include "bdecode.hpp"
#include "bencode.hpp"

using boost::asio::ip::udp;
using boost::asio::io_service;
using boost::asio::ip::address;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;
using boost::asio::buffer;
using boost::system::error_code;

using namespace std::placeholders;

typedef std::array<char, 20> node_id_type;

udp::endpoint target;

void print_usage()
{
	fprintf(stderr, "usage: dht-torture <target-IP> <base client IP>\n");
}

bool compare_id_prefix(char const* id1, char const* id2)
{
	// compare the first 21 bits
	if (id1[0] != id2[0] || id1[1] != id2[1]) return false;
	if ((id1[2] & 0xf8) != (id2[2] & 0xf8)) return false;
	return true;
}

void generate_id(address const& ip_, uint32_t r, char* id)
{
	uint8_t ip[8] = { 0 };
	int ip_len = 0;

	if (ip_.is_v4())
	{
		const static uint8_t mask[] = { 0x03, 0x0f, 0x3f, 0xff };

		address_v4::bytes_type b4;
		b4 = ip_.to_v4().to_bytes();

		for (int i = 0; i < 4; ++i)
			ip[i] = b4[i] & mask[i];

		ip_len = 4;
	}
	else
	{
		const static uint8_t mask[] = { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff };

		address_v6::bytes_type b6;
		b6 = ip_.to_v6().to_bytes();

		for (int i = 0; i < 8; ++i)
			ip[i] = b6[i] & mask[i];

		ip_len = 8;
	}

	uint8_t rand = r & 0x7;
	ip[0] |= rand << 5;

	// this is the crc32c (Castagnoli) polynomial
	boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc;
	crc.process_block(ip, ip + ip_len);
	uint32_t c = crc.checksum();

	id[0] = (c >> 24) & 0xff;
	id[1] = (c >> 16) & 0xff;
	id[2] = ((c >> 8) & 0xf8) | (std::rand() & 0x7);

	for (int i = 3; i < 19; ++i) id[i] = std::rand();
	id[19] = r;
}

size_t build_ip_field(udp::endpoint ep, char* remote_ip)
{
	if (ep.protocol() == udp::v4())
	{
		address_v4::bytes_type ip = ep.address().to_v4().to_bytes();
		memcpy(remote_ip, ip.data(), ip.size());
		remote_ip[ip.size()] = (ep.port() >> 8) & 0xff;
		remote_ip[ip.size() + 1] = ep.port() & 0xff;
		return ip.size() + 2;
	}
	else
	{
		address_v6::bytes_type ip = ep.address().to_v6().to_bytes();
		memcpy(remote_ip, ip.data(), ip.size());
		remote_ip[ip.size()] = (ep.port() >> 8) & 0xff;
		remote_ip[ip.size() + 1] = ep.port() & 0xff;
		return ip.size() + 2;
	}
}

struct client
{
	client(io_service& ios, udp::endpoint ep)
		: sock(ios, ep)
	{
		generate_id(ep.address(), std::rand(), node_id.data());
		sock.async_receive_from(buffer(packet, sizeof(packet)), this->ep
			, std::bind(&client::handle_incoming, this, _1, _2));
	}

	void handle_incoming(error_code const& err, size_t len)
	{
		if (err)
		{
			std::cerr << "Error receiving packet: " << err.message() << std::endl;
			throw boost::system::system_error(err);
		}

		using libtorrent::bdecode_node;
		using libtorrent::bdecode;

		bdecode_node e;
		{
			std::error_code ec;
			int const ret = bdecode(packet, &packet[len], e, ec, nullptr, 5, 100);
			if (ec || ret != 0 || e.type() != bdecode_node::dict_t)
			{
				std::cerr << "Error decoding packet: " << std::string(packet, len) << std::endl;
				return;
			}
		}

		std::string transaction_id = e.dict_find_string_value("t");
		if (transaction_id.empty()) return;

		std::string cmd = e.dict_find_string_value("q");

		bdecode_node a = e.dict_find_dict("a");
		if (!a)
		{
			a = e.dict_find_dict("r");
			if (!a) return;
		}

		bdecode_node const node_id = a.dict_find_string("id");
		if (!node_id || node_id.string_length() != 20) return;

		if (cmd.empty())
		{
			if (transaction_id != "aa")
			{
				std::cerr << "invalid tid: " << transaction_id << std::endl;
				return;
			}

			node_id_type h;
			generate_id(ep.address(), node_id.string_ptr()[19], h.data());
			if (!compare_id_prefix(node_id.string_ptr(), h.data()))
			{
				std::cerr << "invalid node id: " << ep.address().to_string() << ':' << ep.port() << std::endl;
				return;
			}

			// TODO: further response validation

			send_find_node();
		}
		else if (cmd == "ping")
		{
			char response[1500];

			char remote_ip[18];
			size_t remote_ip_len = build_ip_field(ep, remote_ip);

			bencoder b(response, sizeof(response));
			b.open_dict();

			b.add_string("ip");
			b.add_string(remote_ip, remote_ip_len);

			// response dict
			b.add_string("r");
			b.open_dict();

			b.add_string("id");
			b.add_string(this->node_id.data(), this->node_id.size());

			b.close_dict();

			b.add_string("t");
			b.add_string(transaction_id);

			b.add_string("y");
			b.add_string("r");

			b.close_dict();

			boost::system::error_code ec;
			int const len = sock.send_to(buffer(response, b.end() - response), ep, 0, ec);
			if (ec)
			{
				fprintf(stderr, "send_to failed: [cmd: %s dest: %s:%d] (%d) %s\n"
						, cmd.c_str(), ep.address().to_string().c_str()
						, ep.port(), ec.value(), ec.message().c_str());
			}
			else if (len <= 0)
				fprintf(stderr, "send_to failed: return=%d\n", len);
		}

		sock.async_receive_from(buffer(packet, sizeof(packet)), ep
			, std::bind(&client::handle_incoming, this, _1, _2));
	}

	void send_find_node()
	{
		char query[1024];
		bencoder b(query, sizeof(query));
		b.open_dict();

		b.add_string("a");
		b.open_dict();

		b.add_string("id");
		b.add_string(node_id.data(), node_id.size());

		b.add_string("target");
		b.add_string(node_id.data(), node_id.size());

		b.close_dict();

		b.add_string("t");
		b.add_string("aa");

		b.add_string("q");
		b.add_string("find_node");

		b.add_string("y");
		b.add_string("q");

		b.close_dict();

		sock.send_to(buffer(query, b.end() - query), target);
	}

	udp::socket sock;
	node_id_type node_id;

	char packet[1500];
	udp::endpoint ep;
};

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		print_usage();
		return 1;
	}

	target.address(address::from_string(argv[1]));
	target.port(6881);

	io_service ios;

	std::vector<client> clients;
	clients.reserve(512);

	uint32_t base_client_ip = address_v4::from_string(argv[2]).to_ulong();
	for (int i = 0; i < 512; ++i)
	{
		clients.emplace_back(ios, udp::endpoint(address_v4(base_client_ip + i), 6881));
		clients.back().send_find_node();
	}

//	for (;;)
	{
		ios.run();
	}
}
