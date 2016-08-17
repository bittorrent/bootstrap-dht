/*
The MIT License (MIT)

Copyright (c) 2013-2014 BitTorrent Inc.

author: Arvid Norberg, Steven Siloti

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

/*

	To further improve scaling down to small networks:

	* scale the number of threads based on the size of the network.
	  small networks must have just one thread (to consolidate all nodes)

*/

#include <boost/asio.hpp>
#include <thread>
#include <functional>
#include <deque>
#include <chrono>
#include <type_traits>
#include <random>
#include <unordered_set>
#include <set>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <cinttypes> // for PRId64
#include <array>

#include <boost/uuid/sha1.hpp>
#include <boost/crc.hpp>
#include <boost/system/error_code.hpp>
#include <boost/circular_buffer.hpp>

#include "bdecode.hpp"
#include "bencode.hpp"
#include "node_buffer.hpp"
#include "ip_set.hpp"
#include "ping_queue.hpp"

using boost::asio::signal_set;
using boost::asio::io_service;
using boost::asio::ip::udp;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;
using boost::asio::ip::address;
using boost::asio::deadline_timer;
using boost::system::error_code;
using boost::asio::buffer;
using std::chrono::steady_clock;
using std::chrono::minutes;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::duration_cast;
using boost::uuids::detail::sha1;
using namespace std::placeholders;

using time_point = steady_clock::time_point;

using node_id_type = std::array<char, 20>;

const int print_stats_interval = 60;
const int rotate_secrets_interval = 600;
const int nodes_in_response = 16;
int node_buffer_size = 10000000;
int ping_queue_size = 5000000;
bool verify_node_id = true;
int port = 6881;

#ifdef CLIENTS_STAT
std::mutex client_mutex;
std::unordered_map<uint16_t, int> client_histogram;
#endif

/*

	The way the DHT bootstrapping works is by storing all
	nodes in one circular buffer of (IP, port, node-id)-triplets.
	In this circular buffer there are two cursors, one read
	cursor and one write cursor.
	When a find_nodes request comes in, we return the next
	few nodes (or so) under the read cursor and progresses it.

	We remember the node that asked in a separate queue.
	At a later time we ping it. If it responds, we
	add it at the write cursor and progresses it.
	The transaction ID in the ping acts as a SYN-cookie.
	It's set to SHA1(secret, IP, port, node-id), only if
	the response matches the transaction ID will it be
	added to the list of nodes. The secret rotates periodically
	to avoid malicious nodes from inserting themselves
	without us pinging them.

	In addition to this, nodes whose node ID don't match
	the specification at [1] will not be pinged.

	A node's external IP and port is always included
	in all responses.


	[1]: http://libtorrent.org/dht_sec.html

*/

std::atomic<uint64_t> incoming_queries;
std::atomic<uint64_t> invalid_encoding;
std::atomic<uint64_t> invalid_src_address;
std::atomic<uint64_t> failed_nodeid_queries;
std::atomic<uint64_t> outgoing_pings;
std::atomic<uint64_t> short_tid_pongs;
std::atomic<uint64_t> invalid_pongs;
std::atomic<uint64_t> added_nodes;
std::atomic<uint64_t> backup_nodes_returned;

#ifdef DEBUG_STATS
std::atomic<uint32_t> nodebuf_size[4];
#endif

time_point stats_start = steady_clock::now();

#ifdef DEBUG_STATS
std::string suffix(int v)
{
	int i = 0;
	char const* suffixes[] = {"", "k", "M", "G"};
	while (v >= 5000 && i < std::end(suffixes) - std::begin(suffixes) - 1)
	{
		v /= 1000;
		++i;
	}

	char buf[50];
	snprintf(buf, sizeof(buf), "%d%s", v, suffixes[i]);
	return buf;
}
#endif

void print_stats(deadline_timer& stats_timer, error_code const& ec)
{
	if (ec) return;

	time_point now = steady_clock::now();
	float interval = duration_cast<milliseconds>(now - stats_start).count() / 1000.f;
	if (interval <= 0.f) interval = 0.001f;
	stats_start = now;

	printf(
#ifdef DEBUG_STATS
		"node-buf: [%s %s %s %s]"
#endif

		" in: %.1f"
		" invalid_enc: %.1f"
		" invalid_src: %.1f"
		" id_failure: %.1f"
		" out_ping: %.1f"
		" short_tid_pong: %.1f"
		" invalid_pong: %.1f"
		" added: %.1f"
		" backup: %.1f\n"
#ifdef DEBUG_STATS
		, suffix(nodebuf_size[0].load()).c_str()
		, suffix(nodebuf_size[1].load()).c_str()
		, suffix(nodebuf_size[2].load()).c_str()
		, suffix(nodebuf_size[3].load()).c_str()
#endif
		, incoming_queries.exchange(0) / interval
		, invalid_encoding.exchange(0) / interval
		, invalid_src_address.exchange(0) / interval
		, failed_nodeid_queries.exchange(0) / interval
		, outgoing_pings.exchange(0) / interval
		, short_tid_pongs.exchange(0) / interval
		, invalid_pongs.exchange(0) / interval
		, added_nodes.exchange(0) / interval
		, backup_nodes_returned.exchange(0) / interval
		);

#ifdef CLIENTS_STAT
	std::lock_guard<std::mutex> l(client_mutex);
	std::vector<std::pair<int, uint16_t>> ordered;
	for (auto i : client_histogram) {
		ordered.emplace_back(i.second, i.first);
	}
	std::sort(ordered.begin(), ordered.end());
	for (auto i : ordered) {
		printf("[%c%c: %d] ", (i.second >> 8) & 0xff, i.second & 0xff, i.first);
	}
	printf("\n");
	client_histogram.clear();
#endif

	fflush(stdout);

	stats_timer.expires_from_now(boost::posix_time::seconds(print_stats_interval));
	stats_timer.async_wait(std::bind(&print_stats, std::ref(stats_timer), _1));
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

// this is here for backwards compatibility with the first version
// of the node ID scheme, which uses sha1 instead of crc32
void generate_id_sha1(address const& ip_, boost::uint32_t r, char* id)
{
	boost::uint8_t* ip = 0;

	const static boost::uint8_t mask[] = { 0x01, 0x07, 0x1f, 0x7f };

	address_v4::bytes_type b4;
	b4 = ip_.to_v4().to_bytes();
	ip = &b4[0];

	for (int i = 0; i < 4; ++i)
		ip[i] &= mask[i];

	boost::uint8_t rand = r & 0x7;

	// boost's sha1 returns uint32_t's in
	// host endian. We need to turn it into
	// big endian.
	sha1 ctx;
	ctx.process_bytes(ip, 4);
	ctx.process_byte(rand);
	uint32_t d[5];
	ctx.get_digest(d);

	id[0] = (d[0] >> 24) & 0xff;
	id[1] = (d[0] >> 16) & 0xff;
	id[2] = (d[0] >> 8) & 0xff;
	id[3] = d[0] & 0xff;

	for (int i = 4; i < 19; ++i) id[i] = std::rand();
	id[19] = r;
}

struct bound_socket
{
	bound_socket(io_service& ios, udp::endpoint ep)
		: sock(ios)
	{
		error_code ec;
		sock.open(ep.protocol());
		if (ec)
		{
			fprintf(stderr, "socket [%s:%hu]: (%d) %s\n", ep.address().to_string().c_str(), ep.port()
				, ec.value(), ec.message().c_str());
			throw boost::system::system_error(ec);
		}

		{
			boost::asio::socket_base::reuse_address option(true);
			sock.set_option(option);
		}

#if defined(SO_REUSEPORT)
		{
			boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> option(true);
			sock.set_option(option);
		}
#endif

#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		if (ep.address().is_v6())
		{
			boost::asio::detail::socket_option::boolean<IPPROTO_IPV6, IPV6_V6ONLY> option(true);
			sock.set_option(option);
		}
#endif

		sock.bind(ep, ec);
		if (ec)
		{
			fprintf(stderr, "bind [%s:%hu]: (%d) %s\n", ep.address().to_string().c_str(), ep.port()
				, ec.value(), ec.message().c_str());
			throw boost::system::system_error(ec);
		}

		// set send and receive buffers relatively large
		boost::asio::socket_base::receive_buffer_size recv_size(256 * 1024);
		sock.set_option(recv_size);
		boost::asio::socket_base::send_buffer_size send_size(256 * 1024);
		sock.set_option(send_size);

		generate_id(ep.address(), std::rand(), node_id.data());
	}

	udp::socket sock;
	node_id_type node_id;

	// the incoming packet
	char packet[1500];
};

using node_entry_v4 = typename node_buffer<address_v4>::node_entry_t;
using node_entry_v6 = typename node_buffer<address_v6>::node_entry_t;

using node_buffer_v4 = node_buffer<address_v4>;
using node_buffer_v6 = node_buffer<address_v6>;

// TODO: avoid heap allocation here
std::string compute_tid(uint8_t const* secret, char const* remote_ip, size_t ip_len)
{
	sha1 ctx;
	ctx.process_bytes(secret, 20);
	ctx.process_bytes(remote_ip, ip_len);
	uint32_t d[5];
	ctx.get_digest(d);
	std::string ret;
	ret.resize(4);
	ret[0] = (d[0] >> 24) & 0xff;
	ret[1] = (d[0] >> 16) & 0xff;
	ret[2] = (d[0] >> 8) & 0xff;
	ret[3] = d[0] & 0xff;
	return ret;
}

bool verify_tid(std::string tid, uint8_t const* secret1, uint8_t const* secret2
	, char const* remote_ip, size_t ip_len)
{
	// we use 6 byte transaction IDs
	if (tid.size() != 4) return false;

	return compute_tid(secret1, remote_ip, ip_len) == tid
		|| compute_tid(secret2, remote_ip, ip_len) == tid;
}

// determines if an IP is valid to be pinged for
// possible inclusion in our node list
bool is_valid_ip(udp::endpoint const& ep)
{
	if (ep.port() == 0) return false;
	if (ep.protocol() == udp::v4())
	{
		address_v4 const& addr = ep.address().to_v4();
		unsigned long ip = addr.to_ulong();
		if (ip == 0 // 0.0.0.0
			|| (ip & 0xff000000) == 0x0a000000 // 10.x.x.x
			|| (ip & 0xfff00000) == 0xac100000 // 172.16.x.x
			|| (ip & 0xffff0000) == 0xc0a80000 // 192.168.x.x
			|| (ip & 0xffff0000) == 0xa9fe0000 // 169.254.x.x
			|| (ip & 0xff000000) == 0x7f000000) // 127.x.x.x
			return false;
	}
	else
	{
		address_v6 const& addr = ep.address().to_v6();
		if (addr.is_link_local() || addr.is_loopback()
			|| addr.is_multicast() || addr.is_unspecified()
			|| addr.is_site_local() || addr.is_v4_compatible()
			|| addr.is_v4_mapped())
			return false;

		address_v6::bytes_type ip = addr.to_bytes();
		if ((ip[0] & 0xfe) == 0xfc) // unique local address, fc00::/7
			return false;
	}

	return true;
}

std::atomic<uint8_t*> secret1(nullptr);
std::atomic<uint8_t*> secret2(nullptr);
std::atomic<uint8_t*> intermediate(nullptr);

void rotate_secrets(deadline_timer& secrets_timer, std::random_device& r, error_code const& ec)
{
	if (ec) return;

	std::mt19937 rand(r());
	std::uniform_int_distribution<uint8_t> random_byte(0, 0xff);

	// there are three buffers in total and two of
	// them are exposed via secret1 and secret2 at
	// any given time. The old_secret needs to be
	// kept around for a bit to avoid race conditions
	// with threads that may have just grabbed the
	// pointer to it. It's rotated into the intermediate
	// slot.
	uint8_t* old_secret = secret2;
	secret2 = secret1.load();

	uint8_t* i = intermediate.load();
	std::generate(i, i + 20, [&]() { return random_byte(rand); });
	secret1 = i;
	intermediate = old_secret;

	secrets_timer.expires_from_now(boost::posix_time::seconds(rotate_secrets_interval));
	secrets_timer.async_wait(std::bind(&rotate_secrets, std::ref(secrets_timer), std::ref(r), _1));
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

std::array<char, 4> version = {{0, 0, 0, 0}};

std::string storage_filename(char const* base_path, int const threadid, bool const v6)
{
	char name[50];
	std::snprintf(name, sizeof(name), "%s/node-buffer-%d-%s"
		, base_path, threadid, v6 ? "v6" : "v4");
	return name;
}

struct router_thread
{
	router_thread(char const* storage_dir, int const tid, std::vector<address> addrs)
		: ping_queue4(ping_queue_size, steady_clock::now())
		, ping_queue6(ping_queue_size, steady_clock::now())
		, node_buffer4(storage_filename(storage_dir, tid, false).c_str(), node_buffer_size)
		, node_buffer6(storage_filename(storage_dir, tid, true).c_str(), node_buffer_size)
		, last_nodes4(16)
		, last_nodes6(16)
		, signals(ios)
		, threadid(tid)
	{
		for (address a : addrs)
		{
			socks.emplace_back(ios, udp::endpoint(a, port));
		}

		if (socks.empty())
		{
			fprintf(stderr, "no interfaces to receive on\n");
			return;
		}

		signals.add(SIGINT);
		signals.add(SIGTERM);

		// close the sockets and stop the io service when signalled to quit
		signals.async_wait(std::bind(&router_thread::signal_handler, this, _1, _2));
	}

	void signal_handler(error_code const& e, int /*signo*/)
	{
		for (bound_socket& sock : socks)
		{
			error_code ec;
			sock.sock.close(ec);
			if (ec)
				fprintf(stderr, "socket: (%d) %s\n"
					, ec.value(), ec.message().c_str());
		}
		ios.stop();
	}

	void send_ping(queued_node_t const& n)
	{
		//fprintf(stderr, "pinging node\n");
		char remote_ip[18];
		size_t remote_ip_len = build_ip_field(n.ep, remote_ip);
		std::string const transaction_id = compute_tid(secret1, remote_ip, remote_ip_len);
		bound_socket& sock = socks[n.sock_idx];

		// send the ping to this node
		bencoder b(response, sizeof(response));
		b.open_dict();

		b.add_string("ip"); b.add_string(remote_ip, remote_ip_len);

		// args dict
		b.add_string("a");
		b.open_dict();
		b.add_string("id"); b.add_string(sock.node_id.data(), sock.node_id.size());
		b.close_dict();

		b.add_string("t"); b.add_string(transaction_id);
		b.add_string("q"); b.add_string("ping");

		if (version[0] != 0)
		{
			b.add_string("v");
			b.add_string(version.data(), 4);
		}

		b.add_string("y"); b.add_string("q");

		b.close_dict();

		error_code ec;
		int const len = sock.sock.send_to(buffer(response, b.end() - response), n.ep, 0, ec);
		if (ec) {
			fprintf(stderr, "PING send_to failed: (%d) %s (%s:%d)\n"
				, ec.value(), ec.message().c_str()
				, n.ep.address().to_string(ec).c_str(), n.ep.port());
		}
		else if (len <= 0) {
			fprintf(stderr, "PING send_to failed: return=%d\n", len);
		}
		else {
			++outgoing_pings;
		}
	}

	void start()
	{
		printf("starting thread %d\n", threadid);

		for (bound_socket& sock : socks)
		{
			sock.sock.async_receive_from(buffer(sock.packet, sizeof(sock.packet)), ep
				, std::bind(&router_thread::packet_received, this, std::ref(sock), _1, _2));
		}

		for (;;)
		{
#ifdef DEBUG_STATS
			nodebuf_size[threadid] = node_buffer.size();
#endif

			time_point const now = steady_clock::now();

			// if we need to ping nodes, do that now
			queued_node_t n;
			while (ping_queue4.need_ping(&n, now))
				send_ping(n);

			while (ping_queue6.need_ping(&n, now))
				send_ping(n);

			error_code ec;
			size_t const executed = ios.run_one(ec);
			if (ec)
			{
				fprintf(stderr, "error in io service: (%d) %s\n", ec.value(), ec.message().c_str());
				break;
			}

			if (!executed)
			{
				fprintf(stderr, "thread %d stopped\n", threadid);
				break;
			}
		}
	}

	void packet_received(bound_socket& sock, error_code const& ec, size_t len)
	{
		if (ec)
		{
			if (ec == boost::system::errc::bad_file_descriptor
				|| ec == boost::asio::error::operation_aborted)
			{
				printf("stopping thread %d\n", threadid);
				return;
			}
			else if (ec != boost::system::errc::interrupted)
			{
				fprintf(stderr, "receive_from: (%d) %s\n", ec.value(), ec.message().c_str());
				return;
			}
		}
		else
		{
			process_incoming_packet(sock, len);
		}

		sock.sock.async_receive_from(buffer(sock.packet, sizeof(sock.packet)), ep
			, std::bind(&router_thread::packet_received, this, std::ref(sock), _1, _2));
	}

	template <typename Address>
	std::string get_nodes(node_buffer<Address>& buffer
		, boost::circular_buffer<typename node_buffer<Address>::node_entry_t>& last_nodes)
	{
		size_t const entry_size = sizeof(typename node_buffer<Address>::node_entry_t);
		std::string nodes = buffer.get_nodes(nodes_in_response);

		int const num_nodes = nodes.size() / entry_size;
		if (num_nodes < nodes_in_response && last_nodes.size() > 0)
		{
			// fill in with lower quality nodes, since
			nodes.resize((num_nodes + last_nodes.size()) * entry_size);

			// this is just to be able to copy the entire ringbuffer in
			// a single call. find the physical start of its buffer
			void* ptr;
			ptr = (std::min)(last_nodes.array_one().first
				, last_nodes.array_two().first);
			memcpy(&nodes[num_nodes * entry_size]
				, ptr, last_nodes.size() * entry_size);
			++backup_nodes_returned;
		}

		return nodes;
	}

	void process_incoming_packet(bound_socket& sock, size_t const len)
	{
		error_code ec;

		using libtorrent::bdecode_node;
		using libtorrent::bdecode;

		if (ep.port() == 0)
		{
			++invalid_src_address;
			return;
		}

		bool is_v4 = ep.protocol() == udp::v4();

		bdecode_node e;
		std::error_code err;
		int const ret = bdecode(sock.packet, &sock.packet[len], e, err, nullptr, 5, 100);
		if (err || ret != 0 || e.type() != bdecode_node::dict_t)
		{
			++invalid_encoding;
			return;
		}

#ifdef CLIENTS_STAT
		std::string v = e.dict_find_string_value("v");
		if (v.size() >= 2
			&& std::isprint(uint8_t(v[0]))
			&& std::isprint(uint8_t(v[1]))) {
			std::lock_guard<std::mutex> l(client_mutex);
			uint16_t client = (uint8_t(v[0]) << 8) | uint8_t(v[1]);
			++client_histogram[client];
		}
#endif
		//		printf("R: %s\n", print_entry(e, true).c_str());

		if (e.type() != bdecode_node::dict_t)
		{
			++invalid_encoding;
			return;
		}

		// find the interesting fields from the message.
		// i.e. the kind of query, the transaction id and the node id
		std::string transaction_id = e.dict_find_string_value("t");
		if (transaction_id.empty()) return;

		std::string cmd = e.dict_find_string_value("q");

		bdecode_node a = e.dict_find_dict("a");
		if (!a)
		{
			a = e.dict_find_dict("r");
			if (!a) return;
		}
		bdecode_node node_id = a.dict_find_string("id");
		if (!node_id || node_id.string_length() != 20) return;

		// build the IP response buffer, with the source
		// IP and port that we observe from this node
		char remote_ip[18];
		size_t remote_ip_len = build_ip_field(ep, remote_ip);

		if (cmd.empty())
		{
			if (transaction_id.size() != 4)
			{
				++short_tid_pongs;
				return;
			}

			// this is a response, presumably to a ping, since that's
			// the only message we send out

			// if the transaction ID doesn't match, we did not send the ping.
			// ignore it.
			if (!verify_tid(transaction_id, secret1, secret2
				, remote_ip, remote_ip_len))
			{
				++invalid_pongs;
				return;
			}

			// this shouldn't really happen
			if (!is_valid_ip(ep))
				return;

			//			fprintf(stderr, "got ping response\n");

			if (verify_node_id)
			{
				// verify that the node ID is valid for the source IP
				node_id_type h;
				generate_id(ep.address(), node_id.string_ptr()[19], h.data());
				if (!compare_id_prefix(node_id.string_ptr(), h.data()))
				{
					if (ep.address().is_v6())
						return;

					// backwards compatibility. We'll save a lot of CPU
					// once we can remove this
					generate_id_sha1(ep.address(), node_id.string_ptr()[19], h.data());
					if (memcmp(node_id.string_ptr(), h.data(), 4) != 0)
					{
						++failed_nodeid_queries;
						return;
					}
				}
			}

			if (is_v4) {
				added_nodes += node_buffer4.insert_node(ep.address().to_v4()
					, ep.port(), node_id.string_ptr());
			}
			else {
				added_nodes += node_buffer6.insert_node(ep.address().to_v6()
					, ep.port(), node_id.string_ptr());
			}
		}
		else if (cmd == "ping"
			|| cmd == "find_node"
			|| cmd == "get_peers"
			|| cmd == "get")
		{
			bencoder b(response, sizeof(response));
			b.open_dict();

			b.add_string("ip");
			b.add_string(remote_ip, remote_ip_len);

			// response dict
			b.add_string("r");
			b.open_dict();
			b.add_string("id");
			b.add_string(sock.node_id.data(), sock.node_id.size());

			// This is here for backwards compatibility
			// except there is a bug in uTorrent where sending this
			// aborts the bootstrap sequence, causing a 60 second delay
			// for it to be retried (and succeed the second time)
			//			b.add_string("ip");
			//			b.add_string(remote_ip, 4);

			if (cmd != "ping")
			{
				bool want_v4 = false, want_v6 = false;

				bdecode_node const want = a.dict_find_list("want");
				if (want)
				{
					for (int i = 0; i < want.list_size(); ++i)
					{
						bdecode_node const w = want.list_at(i);
						if (w.type() != bdecode_node::string_t) continue;
						if (w.string_length() != 2) continue;
						if (std::memcmp(w.string_ptr(), "n4", 2) == 0)
							want_v4 = true;
						else if (std::memcmp(w.string_ptr(), "n6", 2) == 0)
							want_v6 = true;
					}
				}
				else
				{
					want_v4 = is_v4;
					want_v6 = !is_v4;
				}

				if (want_v4)
				{
					b.add_string("nodes");
					b.add_string(get_nodes(node_buffer4, last_nodes4));
				}

				if (want_v6)
				{
					b.add_string("nodes6");
					b.add_string(get_nodes(node_buffer6, last_nodes6));
				}
			}
			b.close_dict();

			b.add_string("t");
			b.add_string(transaction_id);

			b.add_string("y");
			b.add_string("r");

			if (version[0] != 0)
			{
				b.add_string("v");
				b.add_string(version.data(), 4);
			}

			b.close_dict();
			++incoming_queries;

			int len = sock.sock.send_to(buffer(response, b.end() - response), ep, 0, ec);
			if (ec)
				fprintf(stderr, "send_to failed: [cmd: %s dest: %s:%d] (%d) %s\n"
						, cmd.c_str(), ep.address().to_string().c_str()
						, ep.port(), ec.value(), ec.message().c_str());
			else if (len <= 0)
				fprintf(stderr, "send_to failed: return=%d\n", len);

			// filter obvious invalid IPs
			if (!is_valid_ip(ep)) return;

			// don't save read-only nodes
			bdecode_node ro = e.dict_find_int("ro");
			if (ro && ro.int_value() != 0) return;

			time_point const now = steady_clock::now();

			// don't add the same IP multiple times in a row
			if (is_v4 &&
				(last_nodes4.empty() || last_nodes4.back().ip != ep.address().to_v4().to_bytes()))
			{
				node_entry_v4 e;
				e.ip = ep.address().to_v4().to_bytes();
				e.port = htons(ep.port());
				std::memcpy(e.node_id.data(), node_id.string_ptr(), e.node_id.size());
				last_nodes4.push_back(e);

				// ping this node later, we may want to add it to our node buffer
				ping_queue4.insert_node(ep.address().to_v4(), ep.port()
					, &sock - &socks[0], now);
			}
			else if (!is_v4 &&
				(last_nodes6.empty() || last_nodes6.back().ip != ep.address().to_v6().to_bytes()))
			{
				node_entry_v6 e;
				e.ip = ep.address().to_v6().to_bytes();
				e.port = htons(ep.port());
				std::memcpy(e.node_id.data(), node_id.string_ptr(), e.node_id.size());
				last_nodes6.push_back(e);

				// ping this node later, we may want to add it to our node buffer
				ping_queue6.insert_node(ep.address().to_v6(), ep.port()
					, &sock - &socks[0], now);
			}
		}
	}

	io_service ios;
	std::vector<bound_socket> socks;

	ping_queue<address_v4> ping_queue4;
	ping_queue<address_v6> ping_queue6;
	node_buffer_v4 node_buffer4;
	node_buffer_v6 node_buffer6;

	// always keep the last 16 nodes that have talked to us.
	// these are used as backups when we don't have enough nodes
	// in the node buffer
	boost::circular_buffer<node_entry_v4> last_nodes4;
	boost::circular_buffer<node_entry_v6> last_nodes6;

	udp::endpoint ep;

	// the response packet
	char response[1500];

	signal_set signals;
	int threadid;
};

void print_usage()
{
	fprintf(stderr, "usage: dht-bootstrap <external-IP> [options]\n"
		"\n"
		"OPTIONS:\n"
		"--help                prints this message.\n"
		"--threads <n>         spawns <n> threads (defaults to the\n"
		"                      number of hardware cores).\n"
		"--nodes <n>           sets the number of nodes to keep in\n"
		"                      the node buffer. Once full, the oldest\n"
		"                      nodes are replaced as new nodes come in.\n"
		"--ping-queue <n>      sets the max number of nodes to keep in\n"
		"                      the ping queue. Nodes are held in the queue\n"
		"                      for 15 minutes.\n"
		"--no-verify-id        disable filtering nodes based on their node ID\n"
		"                      and external IP (allow any node in on the\n"
		"                      node list to hand out).\n"
		"--ipv6 <ip>           listen for IPv6 packets on the given address\n"
		"                      can be specified more than once\n"
		"--version <version>   The client version to insert into all outgoing\n"
		"                      packets. The version format must be 2 characters\n"
		"                      followed by a dash and an integer.\n"
		"--dir <path>          specify the directory where the node buckets are\n"
		"                      stored on disk. Defaults to \".\".\n"
		"--port <listen-port>  Sets the port to listen on (for all interfaces)\n"
		"                      defaults to 6881\n"
		"\n"
		"\n"
	);
}

void signal_handler(error_code const& e, int const signo, signal_set& signals
	, deadline_timer& stats_timer, io_service& ios)
{
	error_code ec;
	if (signo == SIGHUP) {

		stats_timer.cancel();
		ios.post(std::bind(&print_stats, std::ref(stats_timer), ec));

		signals.async_wait(std::bind(&signal_handler, _1, _2
			, std::ref(signals), std::ref(stats_timer), std::ref(ios)));
		return;
	}

	ios.stop();
};

std::string operator "" _s(const char* str, size_t len)
{ return std::string(str, len); }

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		print_usage();
		return 1;
	}

	if (argc == 2 && argv[1] == "--help"_s)
	{
		print_usage();
		return 0;
	}

	int num_threads = std::thread::hardware_concurrency();

	std::vector<address> bind_addrs;
	char const* storage_dir = ".";

	error_code ec;

	for (int i = 2; i < argc; ++i)
	{
		if (argv[i] == "--help"_s)
		{
			print_usage();
			return 0;
		}
		else if (argv[i] == "--threads"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--threads expects an integer argument\n");
				return 1;
			}
			num_threads = atoi(argv[i]);
			if (num_threads > std::thread::hardware_concurrency())
			{
				fprintf(stderr, "WARNING: using more threads (%d) than cores (%d)\n"
					, num_threads, std::thread::hardware_concurrency());
			}
			if (num_threads <= 0) num_threads = 1;
		}
		else if (argv[i] == "--nodes"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--nodes expects an integer argument\n");
				return 1;
			}
			node_buffer_size = atoi(argv[i]);
			if (node_buffer_size <= 1000)
			{
				node_buffer_size = 1000;
				fprintf(stderr, "WARNING: node buffer suspiciously small, using %d\n"
					, node_buffer_size);
			}
		}
		else if (argv[i] == "--ping-queue"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--ping-queue expects an integer argument\n");
				return 1;
			}
			ping_queue_size = atoi(argv[i]);
			if (ping_queue_size < 10)
			{
				ping_queue_size = 10;
				fprintf(stderr, "WARNING: ping queue suspiciously small, using %d\n"
					, ping_queue_size);
			}
		}
		else if (argv[i] == "--dir"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--dir expects a directory path argument\n");
				return 1;
			}
			storage_dir = argv[i];
		}
		else if (argv[i] == "--port"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--port expects a port number argument\n");
				return 1;
			}
			port = atoi(argv[i]);
		}
		else if (argv[i] == "--no-verify-id"_s)
		{
			verify_node_id = false;
		}
		else if (argv[i] == "--ipv6"_s)
		{
			++i;
			address_v6 addr = address_v6::from_string(argv[i], ec);
			if (!ec)
				bind_addrs.push_back(addr);
		}
		else if (argv[i] == "--version"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--version expects a version argument\n");
				return 1;
			}

			if (strlen(argv[i]) < 4
				|| !std::isprint(argv[i][0])
				|| !std::isprint(argv[i][1])
				|| argv[i][2] != '-')
			{
				fprintf(stderr, "the version argument is supposed to be CC-N\n"
					"where C is a printable character and N is any number (may be)\n"
					"more than one digit\n");
				return 1;
			}
			version[0] = argv[i][0];
			version[1] = argv[i][1];
			int version_num = atoi(argv[i] + 3);
			version[2] = version_num >> 8;
			version[3] = version_num & 0xff;
		}
		else
		{
			fprintf(stderr, "unknown command line argument: \"%s\"\n", argv[i]);
			print_usage();
			return 1;
		}
	}

	// each thread has its own ping queue, and node_buffer. Each using
	// this limit, so divide it by the number of threads
	ping_queue_size /= num_threads;
	node_buffer_size /= num_threads;

	static_assert(sizeof(node_entry_v4) == 26, "node_entry_t may not contain padding");
	static_assert(sizeof(node_entry_v6) == 38, "node_entry_t may not contain padding");

	{
		address_v4 our_external_ip = address_v4::from_string(argv[1], ec);
		if (ec)
		{
			fprintf(stderr, "invalid external IP address specified \"%s\": (%d) %s\n"
				, argv[1], ec.value(), ec.message().c_str());
			print_usage();
			return 1;
		}

		bind_addrs.push_back(our_external_ip);
	}

	io_service ios;

	deadline_timer stats_timer(ios);
	stats_timer.expires_from_now(boost::posix_time::seconds(print_stats_interval));
	stats_timer.async_wait(std::bind(&print_stats, std::ref(stats_timer), _1));

	std::random_device r;

	{
		std::mt19937 rand(r());
		std::uniform_int_distribution<uint8_t> random_byte(0, 0xff);

		uint8_t* secret = new uint8_t[20];
		std::generate(secret, secret + 20, [&](){ return random_byte(rand);});
		secret1 = secret;
		secret = new uint8_t[20];
		std::generate(secret, secret + 20, [&](){ return random_byte(rand);});
		secret2 = secret;
		intermediate = new uint8_t[20];
	}

	deadline_timer secrets_timer(ios);
	secrets_timer.expires_from_now(boost::posix_time::seconds(rotate_secrets_interval));
	secrets_timer.async_wait(std::bind(&rotate_secrets, std::ref(secrets_timer), std::ref(r), _1));

	std::vector<std::thread> threads;
	threads.reserve(num_threads);
	for (int i = 0; i < num_threads; ++i) {
		threads.emplace_back([=]{
			router_thread t(storage_dir, i, bind_addrs);
			t.start();
		});
	}

	// listen on signals to be able to shut down
	signal_set signals(ios);
	signals.add(SIGINT);
	signals.add(SIGTERM);
	signals.add(SIGHUP);

	// close the socket when signalled to quit
	signals.async_wait(std::bind(&signal_handler, _1, _2
		, std::ref(signals), std::ref(stats_timer), std::ref(ios)));

	ios.run(ec);

	for (auto& i : threads)
		i.join();

	if (ec)
	{
		fprintf(stderr, "io_service: (%d) %s\n", ec.value(), ec.message().c_str());
		return 1;
	}

	delete[] secret1.load();
	delete[] secret2.load();
	delete[] intermediate.load();

	return 0;
}

