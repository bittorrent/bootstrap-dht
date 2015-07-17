/*
The MIT License (MIT)

Copyright (c) 2013-2014 BitTorrent Inc.

author: Arvid Norberg

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

#include <boost/uuid/sha1.hpp>
#include <boost/crc.hpp>
#include <boost/system/error_code.hpp>
#include <boost/circular_buffer.hpp>

#include "lazy_entry.hpp"
#include "bencode.hpp"

using boost::asio::signal_set;
using boost::asio::io_service;
using boost::asio::ip::udp;
using boost::asio::ip::address_v4;
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

typedef steady_clock::time_point time_point;

const int print_stats_interval = 60;
const int nodes_in_response = 16;
int node_buffer_size = 10000000;
int ping_queue_size = 5000000;
bool verify_node_id = true;

#ifdef CLIENTS_STAT
std::mutex client_mutex;
std::unordered_map<uint16_t, int> client_histogram;
#endif

namespace std {

template <>
struct hash<address_v4::bytes_type> : hash<uint32_t>
{
	size_t operator()(address_v4::bytes_type ip) const
	{
		uint32_t arg;
		std::memcpy(&arg, &ip[0], 4);
		return this->hash<uint32_t>::operator()(arg);
	}
};

}

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

// this is the type of each node queued up
// to be pinged at some point in the future
struct queued_node_t
{
	udp::endpoint ep;
	char node_id[20];

	// the time when this node should be pinged
	time_point expire;
};

struct ping_queue_t
{
	ping_queue_t()
		: m_round_robin(0)
		, m_queue_time(0) {}

	// asks the ping-queue if there is another node that
	// should be pinged right now. Returns false if not.
	bool need_ping(queued_node_t* out)
	{
		if (m_queue.empty()) return false;

		time_point now = steady_clock::now();
		if (m_queue.front().expire > now)
			return false;

		*out = m_queue.front();
		m_queue.pop_front();
		m_ips.erase(out->ep);

		assert(out->ep.address() != address_v4::any());

		time_point time_added = out->expire - minutes(15);
		m_queue_time = duration_cast<std::chrono::minutes>(now - time_added).count();

		return true;
	}

	void insert_node(udp::endpoint const& ep, char const* node_id)
	{
		assert(ep.address() != address_v4::any());

		if (m_ips.count(ep)) return;

		// don't let the queue get too big
		if (int(m_queue.size()) > ping_queue_size) return;

		// as the size approaches the limit, increasingly reject
		// new nodes, to distribute nodes we ping more evenly
		// over time
		++m_round_robin;
		m_round_robin &= 0xff;
		if (m_round_robin < int(m_queue.size()) * 256 / ping_queue_size)
			return;

		queued_node_t e;
		e.ep = ep;
		memcpy(e.node_id, node_id, 20);
		// we primarily want to keep quality nodes in our list.
		// in 10 minutes, any pin-hole the node may have had open to
		// us is likely to have been closed. If the node responds
		// in 10 minutes from now, it's likely to either have a full-cone
		// NAT or not be NATed at all (which is the way we like our nodes).
		// also, it still being up is a good predictor for it staying up
		// longer as well.
		e.expire = steady_clock::now() + minutes(15);

		m_queue.push_back(e);
		m_ips.insert(ep);
	}

private:

	// the set of IPs in the queue. An IP is only allowed to appear once
	std::set<udp::endpoint> m_ips;

	// the queue of nodes we should ping, ordered by the
	// time they were added
	std::deque<queued_node_t> m_queue;

	int m_round_robin;

	// the number of seconds nodes stay in the queue
	// before being pinged
	int m_queue_time;
};

// this is the type of each node entry
// in the circular buffer
struct node_entry_t
{
	char node_id[20];
	address_v4::bytes_type ip;
	uint16_t port;
};

struct node_buffer_t
{
	node_buffer_t()
		: m_read_cursor(0)
		, m_write_cursor(0)
		, m_current_max_size(99)
		, m_last_write_loop(steady_clock::now())
	{
		m_buffer.reserve(node_buffer_size);
	}

	bool empty() const { return m_buffer.empty(); }

	int size() const { return m_current_max_size; }

	std::string get_nodes()
	{
		std::string ret;

		if (m_buffer.size() < nodes_in_response)
		{
			ret.resize(m_buffer.size() * sizeof(node_entry_t));
			if (ret.size() > 0)
				memcpy(&ret[0], &m_buffer[0], m_buffer.size() * sizeof(node_entry_t));

			m_read_cursor = 0;
			return ret;
		}

		ret.resize(nodes_in_response * sizeof(node_entry_t));

		if (m_read_cursor == int(m_buffer.size()))
			m_read_cursor = 0;

		if (m_read_cursor <= int(m_buffer.size()) - nodes_in_response)
		{
			memcpy(&ret[0], &m_buffer[m_read_cursor], sizeof(node_entry_t) * nodes_in_response);
			m_read_cursor += nodes_in_response;
			return ret;
		}

		int slice1 = m_buffer.size() - m_read_cursor;
		assert(slice1 < nodes_in_response);
		memcpy(&ret[0], &m_buffer[m_read_cursor], sizeof(node_entry_t) * slice1);
		m_read_cursor += slice1;

		int slice2 = nodes_in_response - slice1;
		memcpy(&ret[slice1 * sizeof(node_entry_t)], &m_buffer[0]
			, sizeof(node_entry_t) * slice2);
		m_read_cursor = slice2;
		return ret;
	}

	void insert_node(udp::endpoint const& ep, char const* node_id)
	{
		node_entry_t e;
		e.ip = ep.address().to_v4().to_bytes();
		e.port = htons(ep.port());
		memcpy(e.node_id, node_id, 20);

		// we're not supposed to add 0.0.0.0
		assert(ep.address() != address_v4::any());

		// only allow once entry per IP
		if (m_ips.count(e.ip)) return;

		auto now = steady_clock::now();
		if (m_write_cursor == m_current_max_size
			&& m_last_write_loop + minutes(15) > now)
		{
			// we're about to wrap the write cursor, but it's been less
			// than 15 minutes since last time we wrapped, so extend
			// the buffer
			m_current_max_size = (std::min)(m_current_max_size * 2, node_buffer_size);
		}

		// this test must be here even though it's also tested
		// in the above if-statement. If we try to grow the buffer
		// size, we may still be stuck at the upper limit, in which
		// case we still need to wrap
		if (m_write_cursor == m_current_max_size)
		{
#ifdef DEBUG_STATS
			printf("write cursor wrapping. %d minutes\n"
				, duration_cast<minutes>(now - m_last_write_loop).count());
#endif
			m_write_cursor = 0;
			m_last_write_loop = now;
		}

		if (int(m_buffer.size()) < m_current_max_size)
		{
			m_buffer.push_back(e);
			m_ips.insert(e.ip);
			++m_write_cursor;
			return;
		}

		// remove the IP we're overwriting from our IP set
		m_ips.erase(m_buffer[m_write_cursor].ip);
		m_buffer[m_write_cursor] = e;
		// and add the one we just put in
		m_ips.insert(e.ip);
		++m_write_cursor;
	}

private:

	int m_read_cursor;
	int m_write_cursor;

	// the current max size we use for the node buffer. If it's churning too
	// frequently, we grow it
	int m_current_max_size;

	// the last time we looped the write cursor. If this is less than 15 minutes
	// we double the size of the buffer (capped at the specified size)
	steady_clock::time_point m_last_write_loop;

	std::vector<node_entry_t> m_buffer;

	// this is a set of all IPs that's currently in the buffer. We only allow
	// one instance of each IP
	std::unordered_set<address_v4::bytes_type> m_ips;
};

char our_node_id[20];


std::string compute_tid(uint8_t const* secret, char const* remote_ip)
{
	sha1 ctx;
	ctx.process_bytes(secret, 20);
	ctx.process_bytes(remote_ip, 6);
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
	, char const* remote_ip)
{
	// we use 6 byte transaction IDs
	if (tid.size() != 4) return false;

	return compute_tid(secret1, remote_ip) == tid
		|| compute_tid(secret2, remote_ip) == tid;
}

bool compare_id_prefix(char const* id1, char const* id2)
{
	// compare the first 21 bytes
	if (id1[0] != id2[0] || id1[1] != id2[1]) return false;
	if ((id1[2] & 0xf8) != (id2[2] & 0xf8)) return false;
	return true;
}

void generate_id(address const& ip_, boost::uint32_t r, char* id)
{
	boost::uint8_t* ip = 0;

	const static boost::uint8_t mask[] = { 0x03, 0x0f, 0x3f, 0xff };

	address_v4::bytes_type b4;
	b4 = ip_.to_v4().to_bytes();
	ip = &b4[0];

	for (int i = 0; i < 4; ++i)
		ip[i] &= mask[i];

	boost::uint8_t rand = r & 0x7;

	// this is the crc32c (Castagnoli) polynomial
	boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc;
	ip[0] |= rand << 5;
	crc.process_block(ip, ip + 4);
	boost::uint32_t c = crc.checksum();

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

// determines if an IP is valid to be pinged for
// possible inclusion in our node list
bool is_valid_ip(udp::endpoint const& ep)
{
	if (ep.port() == 0) return false;
	if (!ep.address().is_v4()) return false;

	address_v4 const& addr = ep.address().to_v4();
	unsigned long ip = addr.to_ulong();
	if (ip == 0 // 0.0.0.0
		|| (ip & 0xff000000) == 0x0a000000 // 10.x.x.x
		|| (ip & 0xfff00000) == 0xac100000 // 172.16.x.x
		|| (ip & 0xffff0000) == 0xc0a80000 // 192.168.x.x
		|| (ip & 0xffff0000) == 0xa9fe0000 // 169.254.x.x
		|| (ip & 0xff000000) == 0x7f000000) // 127.x.x.x
		return false;

	return true;
}

std::atomic<uint8_t*> secret1(nullptr);
std::atomic<uint8_t*> secret2(nullptr);
std::atomic<uint8_t*> intermediate(nullptr);
steady_clock::time_point last_secret_rotate;
std::mutex secret_mutex;

std::array<char, 4> version = {{0, 0, 0, 0}};

void router_thread(int threadid, udp::socket& sock)
{
	printf("starting thread %d\n", threadid);

	ping_queue_t ping_queue;
	node_buffer_t node_buffer;

	// always keep the last 16 nodes that have talked to us.
	// these are used as backups when we don't have enough nodes
	// in the node buffer
	boost::circular_buffer<node_entry_t> last_nodes(nodes_in_response);

	std::random_device r;
	std::mt19937 rand(r());
	std::uniform_int_distribution<uint8_t> random_byte(0, 0xff);

	// the incoming packet
	char packet[1500];

	// the response packet
	char response[1500];

	for (;;)
	{
		udp::endpoint ep;
		error_code ec;

#ifdef DEBUG_STATS
		nodebuf_size[threadid] = node_buffer.size();
#endif

		// rotate the secrets every 10 minutes
		steady_clock::time_point now = steady_clock::now();
		if (last_secret_rotate + minutes(10) < now)
		{
			std::lock_guard<std::mutex> l(secret_mutex);
			if (last_secret_rotate + minutes(10) < now)
			{
				last_secret_rotate = now;

				rand.seed(r());
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
				std::generate(i, i + 20, [&](){ return random_byte(rand);});
				secret1 = i;
				intermediate = old_secret;
			}
		}

		// if we need to ping nodes, do that now
		queued_node_t n;
		while (ping_queue.need_ping(&n))
		{
//			fprintf(stderr, "pinging node\n");
			// build the IP field
			char remote_ip[6];
			address_v4::bytes_type ip = n.ep.address().to_v4().to_bytes();
			memcpy(remote_ip, &ip[0], 4);
			remote_ip[4] = (n.ep.port() >> 8) & 0xff;
			remote_ip[5] = n.ep.port() & 0xff;

			// compute transaction ID
			std::string transaction_id = compute_tid(secret1, remote_ip);

			// send the ping to this node
			bencoder b(response, sizeof(response));
			b.open_dict();

			b.add_string("ip"); b.add_string(remote_ip, 6);

			// args dict
			b.add_string("a");
			b.open_dict();
			b.add_string("id"); b.add_string(our_node_id, 20);
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

			int len = sock.send_to(buffer(response, b.end() - response), n.ep, 0, ec);
			if (ec) {
				fprintf(stderr, "PING send_to failed: (%d) %s (%s:%d)\n"
					, ec.value(), ec.message().c_str()
					, n.ep.address().to_string(ec).c_str(),n.ep.port());
			} else if (len <= 0) {
				fprintf(stderr, "PING send_to failed: return=%d\n", len);
			} else {
				++outgoing_pings;
			}
		}

		int len = sock.receive_from(buffer(packet, sizeof(packet)), ep, 0, ec);
		if (ec)
		{
			if (ec == boost::system::errc::interrupted) continue;
			if (ec == boost::system::errc::bad_file_descriptor
				|| ec == boost::asio::error::operation_aborted)
			{
				printf("stopping thread %d\n", threadid);
				return;
			}
			fprintf(stderr, "receive_from: (%d) %s\n", ec.value(), ec.message().c_str());
			return;
		}

		if (ep.port() == 0)
		{
			++invalid_src_address;
			continue;
		}

		// no support for IPv6
		if (!ep.address().is_v4())
		{
			++invalid_src_address;
			continue;
		}

		using libtorrent::lazy_entry;
		using libtorrent::lazy_bdecode;

		lazy_entry e;
		int ret = lazy_bdecode(packet, &packet[len], e, ec, nullptr, 5, 100);
		if (ec || ret != 0 || e.type() != lazy_entry::dict_t)
		{
			++invalid_encoding;
			continue;
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

		if (e.type() != lazy_entry::dict_t)
		{
			++invalid_encoding;
			continue;
		}

		// find the interesting fields from the message.
		// i.e. the kind of query, the transaction id and the node id
		std::string transaction_id = e.dict_find_string_value("t");
		if (transaction_id.empty()) continue;

		std::string cmd = e.dict_find_string_value("q");

		lazy_entry const* a = e.dict_find_dict("a");
		if (!a)
		{
			a = e.dict_find_dict("r");
			if (!a) continue;
		}
		lazy_entry const* node_id = a->dict_find_string("id");
		if (!node_id || node_id->string_length() != 20) continue;

		// build the IP response buffer, with the source
		// IP and port that we observe from this node
		char remote_ip[6];
		address_v4::bytes_type b = ep.address().to_v4().to_bytes();
		memcpy(remote_ip, &b[0], 4);
		remote_ip[4] = (ep.port() >> 8) & 0xff;
		remote_ip[5] = ep.port() & 0xff;

		if (cmd.empty())
		{
			if (transaction_id.size() != 4)
			{
				++short_tid_pongs;
				continue;
			}

			// this is a response, presumably to a ping, since that's
			// the only message we send out

			// if the transaction ID doesn't match, we did not send the ping.
			// ignore it.
			if (!verify_tid(transaction_id, secret1, secret2
				, remote_ip))
			{
				++invalid_pongs;
				continue;
			}

			// this shouldn't really happen
			if (!is_valid_ip(ep))
				continue;

//			fprintf(stderr, "got ping response\n");

			if (verify_node_id)
			{
				// verify that the node ID is valid for the source IP
				char h[20];
				generate_id(ep.address(), node_id->string_ptr()[19], h);
				if (!compare_id_prefix(node_id->string_ptr(), &h[0]))
				{
					// backwards compatibility. We'll save a lot of CPU
					// once we can remove this
					generate_id_sha1(ep.address(), node_id->string_ptr()[19], h);
					if (memcmp(node_id->string_ptr(), &h[0], 4) != 0)
					{
						++failed_nodeid_queries;
						continue;
					}
				}
			}

			++added_nodes;
			node_buffer.insert_node(ep, node_id->string_ptr());
		}
		else if (cmd == "ping"
			|| cmd == "find_node"
			|| cmd == "get_peers"
			|| cmd == "get")
		{
			bencoder b(response, sizeof(response));
			b.open_dict();

			b.add_string("ip");
			b.add_string(remote_ip, 6);

			// response dict
			b.add_string("r");
			b.open_dict();
			b.add_string("id");
			b.add_string(our_node_id, 20);

			// This is here for backwards compatibility
			// except there is a bug in uTorrent where sending this
			// aborts the bootstrap sequence, causing a 60 second delay
			// for it to be retried (and succeed the second time)
//			b.add_string("ip");
//			b.add_string(remote_ip, 4);

			if (cmd != "ping")
			{
				b.add_string("nodes");
				std::string nodes = node_buffer.get_nodes();
				int num_nodes = nodes.size() / sizeof(node_entry_t);
				if (num_nodes < nodes_in_response && last_nodes.size() > 0)
				{
					// fill in with lower quality nodes, since
					nodes.resize((num_nodes + last_nodes.size()) * sizeof(node_entry_t));

					// this is just to be able to copy the entire ringbuffer in
					// a single call. find the physical start of its buffer
					node_entry_t* ptr = (std::min)(last_nodes.array_one().first
						, last_nodes.array_two().first);
					memcpy(&nodes[num_nodes * sizeof(node_entry_t)]
						, ptr, last_nodes.size() * sizeof(node_entry_t));
					++backup_nodes_returned;
				}
				b.add_string(nodes);
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

			int len = sock.send_to(buffer(response, b.end() - response), ep, 0, ec);
			if (ec)
				fprintf(stderr, "send_to failed: [cmd: %s dest: %s:%d] (%d) %s\n"
					, cmd.c_str(), ep.address().to_string().c_str()
					, ep.port(), ec.value(), ec.message().c_str());
			else if (len <= 0)
				fprintf(stderr, "send_to failed: return=%d\n", len);

			// filter obvious invalid IPs, and IPv6 (since we only support
			// IPv4 for now)
			if (!is_valid_ip(ep)) continue;

			// don't save read-only nodes
			lazy_entry const* ro = e.dict_find_int("ro");
			if (ro && ro->int_value() != 0) continue;

			// don't add the same IP multiple times in a row
			if (last_nodes.empty() || last_nodes.back().ip != ep.address().to_v4().to_bytes())
			{
				node_entry_t e;
				e.ip = ep.address().to_v4().to_bytes();
				e.port = htons(ep.port());
				memcpy(e.node_id, node_id, 20);
				last_nodes.push_back(e);
			}

			// ping this node later, we may want to add it to our node buffer
			ping_queue.insert_node(ep, node_id->string_ptr());
		}
	}
}

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
		"--version <version>   The client version to insert into all outgoing\n"
		"                      packets. The version format must be 2 characters\n"
		"                      followed by a dash and an integer.\n"
		"\n"
		"\n"

	);
}

void signal_handler(error_code const& e, int signo, signal_set& signals
	, deadline_timer& stats_timer, udp::socket& sock, io_service& ios)
{
	error_code ec;
	if (signo == SIGHUP) {

		stats_timer.cancel();
		ios.post(std::bind(&print_stats, std::ref(stats_timer), ec));

		signals.async_wait(std::bind(&signal_handler, _1, _2
			, std::ref(signals), std::ref(stats_timer), std::ref(sock)
			, std::ref(ios)));
		return;
	}

	stats_timer.cancel();
	sock.close(ec);
	if (ec)
		fprintf(stderr, "socket: (%d) %s\n"
			, ec.value(), ec.message().c_str());
};

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		print_usage();
		return 1;
	}

	int num_threads = std::thread::hardware_concurrency();

	for (int i = 2; i < argc; ++i)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			print_usage();
			return 0;
		}
		else if (strcmp(argv[i], "--threads") == 0)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--threads expects an integer argument\n");
				return 1;
			}
			num_threads = atoi(argv[i]);
			if (num_threads <= 0)
			{
				num_threads = 1;
			}
			else if (unsigned(num_threads) > std::thread::hardware_concurrency())
			{
				fprintf(stderr, "WARNING: using more threads (%d) than cores (%d)\n"
					, num_threads, std::thread::hardware_concurrency());
			}
		}
		else if (strcmp(argv[i], "--nodes") == 0)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--nodes expects an integer argument\n");
				return 1;
			}
			int size = atoi(argv[i]);
			if (size <= 1000)
			{
				size = 1000;
				fprintf(stderr, "WARNING: node buffer suspiciously small, using %d\n"
					, size);
			}
			node_buffer_size = size;
		}
		else if (strcmp(argv[i], "--ping-queue") == 0)
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--ping-queue expects an integer argument\n");
				return 1;
			}
			int size = atoi(argv[i]);
			if (size < 10)
			{
				size = 10;
				fprintf(stderr, "WARNING: ping queue suspiciously small, using %d\n"
					, size);
			}
			ping_queue_size = size;
		}
		else if (strcmp(argv[i], "--no-verify-id") == 0)
		{
			verify_node_id = false;
		}
		else if (strcmp(argv[i], "--version") == 0)
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
	}

	// each thread has its own ping queue, and node_buffer. Each using
	// this limit, so divide it by the number of threads
	ping_queue_size /= num_threads;
	node_buffer_size /= num_threads;

	static_assert(sizeof(node_entry_t) == 26, "node_entry_t may not contain padding");

	error_code ec;
	address_v4 our_external_ip = address_v4::from_string(argv[1], ec);
	if (ec)
	{
		fprintf(stderr, "invalid external IP address specified: %s\n"
			, ec.message().c_str());
		return 1;
	}

	io_service ios;
	udp::socket sock(ios);

	sock.open(udp::v4(), ec);
	if (ec)
	{
		fprintf(stderr, "socket: (%d) %s\n", ec.value(), ec.message().c_str());
		return 1;
	}

	boost::asio::socket_base::reuse_address option(true);
	sock.set_option(option, ec);
	if (ec)
	{
		fprintf(stderr, "reuse address: (%d) %s\n", ec.value(), ec.message().c_str());
		return 1;
	}

	sock.bind(udp::endpoint(our_external_ip, 6881), ec);
	if (ec)
	{
		fprintf(stderr, "bind: (%d) %s\n", ec.value(), ec.message().c_str());
		return 1;
	}

	// set send and receive buffers relatively large
	boost::asio::socket_base::receive_buffer_size recv_size(512 * 1024);
	sock.set_option(recv_size);
	boost::asio::socket_base::send_buffer_size send_size(512 * 1024);
	sock.set_option(send_size);

	// initialize our_node_id
	generate_id(our_external_ip, std::rand(), our_node_id);

	deadline_timer stats_timer(ios);
	stats_timer.expires_from_now(boost::posix_time::seconds(print_stats_interval));
	stats_timer.async_wait(std::bind(&print_stats, std::ref(stats_timer), _1));

	// listen on signals to be able to shut down
	signal_set signals(ios);
	signals.add(SIGINT);
	signals.add(SIGTERM);
	signals.add(SIGHUP);

	// close the socket when signalled to quit
	signals.async_wait(std::bind(&signal_handler, _1, _2
		, std::ref(signals), std::ref(stats_timer), std::ref(sock)
		, std::ref(ios)));

	std::random_device r;
	std::mt19937 rand(r());
	std::uniform_int_distribution<uint8_t> random_byte(0, 0xff);

	uint8_t* secret = new uint8_t[20];
	std::generate(secret, secret + 20, [&](){ return random_byte(rand);});
	secret1 = secret;
	secret = new uint8_t[20];
	std::generate(secret, secret + 20, [&](){ return random_byte(rand);});
	secret2 = secret;
	intermediate = new uint8_t[20];
	last_secret_rotate = steady_clock::now();

	std::vector<std::thread> threads;
	threads.reserve(num_threads);
	for (int i = 0; i < num_threads; ++i)
		threads.emplace_back(&router_thread, i, std::ref(sock));

	ios.run(ec);
	if (ec)
	{
		fprintf(stderr, "io_service: (%d) %s\n", ec.value(), ec.message().c_str());
		return 1;
	}

	for (auto& i : threads)
		i.join();

	delete[] secret1.load();
	delete[] secret2.load();
	delete[] intermediate.load();

	return 0;
}

