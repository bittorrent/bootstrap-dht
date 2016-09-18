/*
The MIT License (MIT)

Copyright (c) 2013-2014 BitTorrent Inc.
Copyright (c) 2016 Arvid Norberg

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
#include <boost/asio/steady_timer.hpp>

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
using boost::asio::steady_timer;
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
int nodes_in_response = 16;
int node_buffer_size = 10000000;
int ping_queue_size = 5000000;
bool verify_node_id = true;
bool cross_pollinate = false;
udp::endpoint bootstrap_node;
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

std::atomic<uint32_t> responses;
std::atomic<uint32_t> incoming_duplicates;
std::atomic<uint32_t> invalid_req;
std::atomic<uint32_t> invalid_src_address;
std::atomic<uint32_t> failed_nodeid_queries;
std::atomic<uint32_t> outgoing_pings;
std::atomic<uint32_t> invalid_pongs;
std::atomic<uint32_t> added_nodes;
std::atomic<uint32_t> backup_nodes4_returned;
std::atomic<uint32_t> backup_nodes6_returned;

#ifdef DEBUG_STATS
// 0: IPv4 buffer size
// 1: IPv6 buffer size
std::array<std::atomic<uint32_t>, 2> nodebuf_size;
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

void print_stats(steady_timer& stats_timer, error_code const& ec)
{
	if (ec) return;

	time_point const now = steady_clock::now();

#ifdef CLIENTS_STAT
	std::vector<std::pair<int, uint16_t>> ordered;
	{
		std::lock_guard<std::mutex> l(client_mutex);
		for (auto i : client_histogram) {
			ordered.emplace_back(i.second, i.first);
		}
		client_histogram.clear();
	}
	std::sort(ordered.begin(), ordered.end());
	char client_dist[200];
	client_dist[0] = '\0';
	int len = 0;
	for (auto i : ordered) {
		len += snprintf(client_dist + len, sizeof(client_dist) - len
			, "[%c%c: %d] ", (i.second >> 8) & 0xff, i.second & 0xff, i.first);
	}
#endif

	// every 40th line is a repeat of the header
	static std::uint8_t cnt = 0;
	if (cnt == 0)
	{
		printf("%7s%10s%10s%10s%10s%10s%10s%10s%10s%10s%10s"
#ifdef DEBUG_STATS
			"%8s%8s"
#endif
#ifdef CLIENTS_STAT
			" %s"
#endif
			"\n"
			, "time(s)", "dup-ip", "inv-msg", "inv-src", "resp"
			, "id-fail", "out-ping", "inv-pong", "added", "backup4", "backup6"
#ifdef DEBUG_STATS
			, "buf4", "buf6"
#endif
#ifdef CLIENTS_STAT
			, "client distribution"
#endif
			);
	}
	cnt = (cnt + 1) % 40;

	printf("%7" PRId64 "%10u%10u%10u%10u%10u%10u%10u%10u%10u%10u"
#ifdef DEBUG_STATS
		"%8s%8s"
#endif
#ifdef CLIENTS_STAT
		" %s"
#endif
		"\n"
		, duration_cast<seconds>(now - stats_start).count()
		, incoming_duplicates.exchange(0)
		, invalid_req.exchange(0)
		, invalid_src_address.exchange(0)
		, responses.exchange(0)
		, failed_nodeid_queries.exchange(0)
		, outgoing_pings.exchange(0)
		, invalid_pongs.exchange(0)
		, added_nodes.exchange(0)
		, backup_nodes4_returned.exchange(0)
		, backup_nodes6_returned.exchange(0)
#ifdef DEBUG_STATS
		, suffix(nodebuf_size[0].load()).c_str()
		, suffix(nodebuf_size[1].load()).c_str()
#endif
#ifdef CLIENTS_STAT
		, client_dist
#endif
		);

	stats_start = now;

	fflush(stdout);

	stats_timer.expires_from_now(seconds(print_stats_interval));
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
	udp::endpoint ep;

	// the incoming packet
	char packet[1500];
};

using node_entry_v4 = typename node_buffer<address_v4>::node_entry_t;
using node_entry_v6 = typename node_buffer<address_v6>::node_entry_t;

using node_buffer_v4 = node_buffer<address_v4>;
using node_buffer_v6 = node_buffer<address_v6>;

std::array<char, 4> compute_tid(uint8_t const* secret, char const* remote_ip
	, size_t const ip_len)
{
	sha1 ctx;
	ctx.process_bytes(secret, 20);
	ctx.process_bytes(remote_ip, ip_len);
	std::uint32_t d[5];
	ctx.get_digest(d);
	return {{
		char((d[0] >> 24) & 0xff),
		char((d[0] >> 16) & 0xff),
		char((d[0] >> 8) & 0xff),
		char(d[0] & 0xff)
	}};
}

bool verify_tid(span<char> tid, uint8_t const* secret1, uint8_t const* secret2
	, char const* remote_ip, size_t ip_len)
{
	// we use 6 byte transaction IDs
	if (tid.size() != 4) return false;

	return compute_tid(secret1, remote_ip, ip_len) == tid
		|| compute_tid(secret2, remote_ip, ip_len) == tid;
}

// determines if an IP is valid to be pinged for
// possible inclusion in our node list
bool is_valid_ep(udp::endpoint const& ep)
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

void rotate_secrets(steady_timer& secrets_timer, std::random_device& r, error_code const& ec)
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

	secrets_timer.expires_from_now(seconds(rotate_secrets_interval));
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

bool check_duplicate(address const& a, ip_set<address_v4>& recent4, ip_set<address_v6>& recent6)
{
	if (a.is_v4())
	{
		// without an upper limit, we would be vulnerable to a DoS
		// attack by spoofed source IPs.
		if (recent4.size() > 4000000) return recent4.count(a.to_v4());

		// insert returns true if the insertion took place
		// i.e. it was not already in there, not a duplicate
		return recent4.insert(a.to_v4()) == false;
	}
	if (recent6.size() > 4000000) return recent6.count(a.to_v6());
	return recent6.insert(a.to_v6()) == false;
}

template<typename Address>
void inc_backup_counter();

template<>
void inc_backup_counter<address_v4>()
{ ++backup_nodes4_returned; }

template<>
void inc_backup_counter<address_v6>()
{ ++backup_nodes6_returned; }

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
		char remote_ip[18];
		size_t remote_ip_len = build_ip_field(n.ep, remote_ip);
		std::array<char, 4> transaction_id = compute_tid(secret1, remote_ip, remote_ip_len);
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

	void send_request(queued_node_t const& n)
	{
		char remote_ip[18];
		size_t remote_ip_len = build_ip_field(n.ep, remote_ip);
		std::array<char, 4> transaction_id = compute_tid(secret1, remote_ip, remote_ip_len);
		bound_socket& sock = socks[n.sock_idx];

		// send find_nodes to this node
		bencoder b(response, sizeof(response));
		b.open_dict();

		// args dict
		b.add_string("a");
		b.open_dict();
		b.add_string("id"); b.add_string(sock.node_id.data(), sock.node_id.size());
		char random_target[20];
		std::generate(random_target, random_target + 20, &std::rand);
		b.add_string("target"); b.add_string(random_target, sizeof(random_target));
		b.add_string("want");
		{
			b.open_list();
			b.add_string("n4");
			b.add_string("n6");
			b.close_list();
		}
		b.close_dict();

		b.add_string("t"); b.add_string(transaction_id);
		b.add_string("q"); b.add_string("find_node");

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
			fprintf(stderr, "FIND_NODE send_to failed: (%d) %s (%s:%d)\n"
				, ec.value(), ec.message().c_str()
				, n.ep.address().to_string(ec).c_str(), n.ep.port());
		}
		else if (len <= 0) {
			fprintf(stderr, "FIND_NODE send_to failed: return=%d\n", len);
		}
	}

	void start()
	{
		printf("starting thread %d\n", threadid);

		for (bound_socket& sock : socks)
		{
			sock.sock.async_receive_from(buffer(sock.packet, sizeof(sock.packet))
				, sock.ep, std::bind(&router_thread::packet_received, this, std::ref(sock), _1, _2));
		}

		time_point last_cross_pollinate = steady_clock::now();
		time_point last_reset_recent = steady_clock::now();
		for (;;)
		{
#ifdef DEBUG_STATS
			if (threadid == 0) {
				nodebuf_size[0] = node_buffer4.size();
				nodebuf_size[1] = node_buffer6.size();
			}
#endif

			time_point const now = steady_clock::now();

			if (cross_pollinate
				&& now - last_cross_pollinate > minutes(10)
				&& ping_queue4.size() + ping_queue6.size() < 16)
			{
				last_cross_pollinate = now;
				send_request({bootstrap_node, 0});
			}

			if (now - last_reset_recent > minutes(10))
			{
				// reset the recent node sets regularly, to allow
				// nodes to send another request
				last_reset_recent = now;
				recent_reqs4.clear();
				recent_reqs6.clear();
			}

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

		sock.sock.async_receive_from(buffer(sock.packet, sizeof(sock.packet)), sock.ep
			, std::bind(&router_thread::packet_received, this, std::ref(sock), _1, _2));
	}

	template <typename Address>
	std::array<span<char const>, 3> get_nodes(node_buffer<Address>& buffer
		, boost::circular_buffer<typename node_buffer<Address>::node_entry_t> const& last_nodes
		, int const requested_nodes)
	{
		size_t const entry_size = sizeof(typename node_buffer<Address>::node_entry_t);
		auto const ranges = buffer.get_nodes(requested_nodes);

		size_t len = 0;
		for (auto const& r : ranges) len += r.size();

		int const num_nodes = len / entry_size;
		if (num_nodes >= requested_nodes || last_nodes.empty())
		{
			return {{ranges[0], ranges[1], {}}};
		}

		// this is just to be able to copy the entire ringbuffer in
		// a single call. find the physical start of its buffer
		char const* ptr = reinterpret_cast<char const*>((std::min)(last_nodes.array_one().first
			, last_nodes.array_two().first));
		size_t const missing_nodes = requested_nodes - num_nodes;
		inc_backup_counter<Address>();
		return {{ranges[0], ranges[1]
			, {ptr, std::min(missing_nodes, last_nodes.size()) * entry_size}}};
	}

	void process_incoming_packet(bound_socket& sock, size_t const len)
	{
		error_code ec;

		using libtorrent::bdecode_node;
		using libtorrent::bdecode;

		if (!is_valid_ep(sock.ep))
		{
			++invalid_src_address;
			return;
		}

		bool const is_v4 = sock.ep.protocol() == udp::v4();

		bdecode_node e;
		std::error_code err;
		int const ret = bdecode(sock.packet, &sock.packet[len], e, err, nullptr, 5, 100);
		if (err || ret != 0 || e.type() != bdecode_node::dict_t)
		{
			++invalid_req;
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
		if (e.type() != bdecode_node::dict_t)
		{
			++invalid_req;
			return;
		}

		// find the interesting fields from the message.
		// i.e. the kind of query, the transaction id and the node id
		std::string transaction_id = e.dict_find_string_value("t");
		if (transaction_id.empty())
		{
			++invalid_req;
			return;
		}

		std::string cmd = e.dict_find_string_value("q");

		bdecode_node a = e.dict_find_dict("a");
		if (!a)
		{
			a = e.dict_find_dict("r");
			if (!a)
			{
				++invalid_req;
				return;
			}
		}
		bdecode_node node_id = a.dict_find_string("id");
		if (!node_id || node_id.string_length() != 20)
		{
			++invalid_req;
			return;
		}

		// build the IP response buffer, with the source
		// IP and port that we observe from this node
		char remote_ip[18];
		size_t remote_ip_len = build_ip_field(sock.ep, remote_ip);

		if (cmd.empty())
		{
			// this is a response to one of our pings
			// or find_nodes requests
			if (transaction_id.size() != 4)
			{
				++invalid_pongs;
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

			if (verify_node_id)
			{
				// verify that the node ID is valid for the source IP
				node_id_type h;
				generate_id(sock.ep.address(), node_id.string_ptr()[19], h.data());
				if (!compare_id_prefix(node_id.string_ptr(), h.data()))
				{
					if (sock.ep.address().is_v6())
					{
						++failed_nodeid_queries;
						return;
					}

					// backwards compatibility. We'll save a lot of CPU
					// once we can remove this
					generate_id_sha1(sock.ep.address(), node_id.string_ptr()[19], h.data());
					if (memcmp(node_id.string_ptr(), h.data(), 4) != 0)
					{
						++failed_nodeid_queries;
						return;
					}
				}
			}

			if (cross_pollinate && sock.ep == bootstrap_node)
			{
				// this is a response from the other bootstrap node
				// put the nodes in the response in the ping queue
				{
					std::string nodes4 = a.dict_find_string_value("nodes", "");
					fprintf(stderr, "received %d nodes4 from x-pollinate node\n"
						, int(nodes4.size() / 26));
					char const* end = nodes4.data() + nodes4.size();
					for (char const* i = nodes4.data(); end - i >= 6 + 20; i += 6 + 20)
					{
						address_v4::bytes_type b;
						std::memcpy(b.data(), i, b.size());
						int const port = (unsigned(i[4]) << 8) | unsigned(i[5]);
						added_nodes += node_buffer4.insert_node(address_v4(b)
							, port, i + 6);
					}
				}

				{
					std::string nodes6 = a.dict_find_string_value("nodes6", "");
					fprintf(stderr, "received %d nodes6 from x-pollinate node\n"
						, int(nodes6.size() / 38));
					char const* end = nodes6.data() + nodes6.size();
					for (char const* i = nodes6.data(); end - i >= 18 + 20; i += 18 + 20)
					{
						address_v6::bytes_type b;
						std::memcpy(b.data(), i, b.size());
						int const port = (unsigned(i[16]) << 8) | unsigned(i[17]);
						added_nodes += node_buffer6.insert_node(address_v6(b)
							, port, i + 18);
					}
				}
			}

			if (is_v4) {
				added_nodes += node_buffer4.insert_node(sock.ep.address().to_v4()
					, sock.ep.port(), node_id.string_ptr());
			}
			else {
				added_nodes += node_buffer6.insert_node(sock.ep.address().to_v6()
					, sock.ep.port(), node_id.string_ptr());
			}
		}
		else if (cmd == "ping"
			|| cmd == "find_node"
			|| cmd == "get_peers"
			|| cmd == "get")
		{
			insert_response inserted = insert_response::inserted;

			// don't save read-only nodes
			// for obvious invalid IPs
			bdecode_node ro = e.dict_find_int("ro");
			if (!ro || ro.int_value() == 0)
			{
				time_point const now = steady_clock::now();

				if (is_v4)
				{
					node_entry_v4 e;
					e.ip = sock.ep.address().to_v4().to_bytes();
					e.port = htons(sock.ep.port());
					std::memcpy(e.node_id.data(), node_id.string_ptr(), e.node_id.size());

					if (!last_nodes4.empty()
						&& last_nodes4.back().ip == e.ip)
					{
						++incoming_duplicates;
						return;
					}
					last_nodes4.push_back(e);

					// ping this node later, we may want to add it to our node buffer
					inserted = ping_queue4.insert_node(
						sock.ep.address().to_v4(), sock.ep.port()
						, &sock - &socks[0], now);
				}
				else
				{
					node_entry_v6 e;
					e.ip = sock.ep.address().to_v6().to_bytes();
					e.port = htons(sock.ep.port());
					std::memcpy(e.node_id.data(), node_id.string_ptr(), e.node_id.size());

					if (!last_nodes6.empty()
						&& last_nodes6.back().ip == e.ip)
					{
						++incoming_duplicates;
						return;
					}
					last_nodes6.push_back(e);

					// ping this node later, we may want to add it to our node buffer
					inserted = ping_queue6.insert_node(
						sock.ep.address().to_v6(), sock.ep.port()
						, &sock - &socks[0], now);
				}
			}

			bool const is_duplicate = (inserted == insert_response::duplicate)
				|| check_duplicate(sock.ep.address(), recent_reqs4, recent_reqs6);

			if (is_duplicate) ++incoming_duplicates;

			bencoder b(response, sizeof(response));
			b.open_dict();

			b.add_string("ip");
			b.add_string(remote_ip, remote_ip_len);

			// response dict
			b.add_string("r");
			b.open_dict();
			b.add_string("id");
			b.add_string(sock.node_id.data(), sock.node_id.size());

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

				// only return three nodes to duplicate requests, to save bandwidth
				int const num_nodes = is_duplicate
					? std::min(3, nodes_in_response) : nodes_in_response;

				if (want_v4)
				{
					b.add_string("nodes");
					auto const node_ranges = get_nodes(node_buffer4, last_nodes4, num_nodes);
					b.add_string_concatenate(node_ranges);
				}

				if (want_v6)
				{
					b.add_string("nodes6");
					auto const node_ranges = get_nodes(node_buffer6, last_nodes6, num_nodes);
					b.add_string_concatenate(node_ranges);
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
			++responses;

			int len = sock.sock.send_to(buffer(response, b.end() - response), sock.ep, 0, ec);
			if (ec)
				fprintf(stderr, "send_to failed: [cmd: %s dest: %s:%d] (%d) %s\n"
						, cmd.c_str(), sock.ep.address().to_string().c_str()
						, sock.ep.port(), ec.value(), ec.message().c_str());
			else if (len <= 0)
				fprintf(stderr, "send_to failed: return=%d\n", len);
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

	// the IP of every request is inserted in one of these sets. If we receive
	// a request from an IP that's already in here, we return fewer nodes
	ip_set<address_v4> recent_reqs4;
	ip_set<address_v6> recent_reqs6;

	// we handle one request at a time (per thread), this is the buffer we
	// build the response in
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
		"--response-size <n>   Specifies the number of DHT nodes to return in\n"
		"                      response to a query. Defaults to 16\n"
		"--x-pollinate <ip> <port>\n"
		"                      if the ping queue becomes too small, request more\n"
		"                      nodes from this DHT node.\n"
		"\n"
		"\n"
	);
}

void signal_handler(error_code const& e, int const signo, signal_set& signals
	, steady_timer& stats_timer, io_service& ios)
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
		else if (argv[i] == "--response-size"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--response-size expects a number argument\n");
				return 1;
			}
			nodes_in_response = atoi(argv[i]);
			if (nodes_in_response <= 0)
			{
				fprintf(stderr, "invalid number of nodes: %d\n", nodes_in_response);
				return 1;
			}
		}
		else if (argv[i] == "--x-pollinate"_s)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--x-pollinate expects an IP argument\n");
				return 1;
			}
			error_code ec;
			bootstrap_node.address(address::from_string(argv[i], ec));
			if (ec)
			{
				fprintf(stderr, "invalid IP argument \"%s\": %s\n"
					, argv[i], ec.message().c_str());
				return 1;
			}
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--x-pollinate expects a port argument\n");
				return 1;
			}
			bootstrap_node.port(atoi(argv[i]));
			cross_pollinate = true;
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

	steady_timer stats_timer(ios);
	stats_timer.expires_from_now(seconds(print_stats_interval));
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

	steady_timer secrets_timer(ios);
	secrets_timer.expires_from_now(seconds(rotate_secrets_interval));
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

