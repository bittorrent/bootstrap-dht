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

#pragma once

#include <boost/asio/ip/udp.hpp>
#include <chrono>
#include <deque>

#include "ip_set.hpp"

using boost::asio::ip::udp;
using std::chrono::duration_cast;
using std::chrono::minutes;
using std::chrono::seconds;

struct queued_node_t
{
	udp::endpoint ep;
	int sock_idx;
};

enum class insert_response
{
	inserted,
	duplicate,
	full
};

template <typename Address>
struct ping_queue
{
	using steady_clock = std::chrono::steady_clock;
	using time_point = steady_clock::time_point;

	ping_queue(size_t const capacity, time_point const now)
		: m_capacity(capacity)
		, m_created(now)
	{}

	size_t size() const
	{
		return m_queue.size();
	}

	// asks the ping-queue if there is another node that
	// should be pinged right now. Returns false if not.
	bool need_ping(queued_node_t* out, time_point const now)
	{
		if (m_queue.empty()) return false;

		// this is the number of seconds since the queue was constructed. This is
		// compared against the expiration times on the queue entries
		int const time_out = duration_cast<std::chrono::seconds>(
			now - m_created).count();

		if (m_queue.front().expire > time_out) return false;
		auto ent = m_queue.front();
		m_queue.pop_front();
		m_ips.erase(Address(ent.addr));

		out->ep = udp::endpoint(Address(ent.addr), ent.port);
		out->sock_idx = ent.sock_idx;

		return true;
	}

	// returns whether the node was inserted or not
	insert_response insert_node(Address const& addr, std::uint16_t const port
		, int const sock_idx, time_point const now)
	{
		assert(addr != Address::any());
		assert(now >= m_created);

		// prevent duplicate entries
		if (m_ips.count(addr)) return insert_response::duplicate;

		// the number of nodes we allow in the queue before we start dropping
		// nodes (to stay below the limi)
		size_t const low_watermark = m_capacity / 2;

		if (m_queue.size() > low_watermark) {
			// as the size approaches the limit, increasingly reject
			// new nodes, to distribute nodes we ping more evenly
			// over time.
			// we don't start dropping nodes until we exceed the low watermark, but
			// once we do, we increase the drop rate the closer we get to the limit
			++m_round_robin;
			if (m_round_robin < (m_queue.size() - low_watermark) * 256 / (m_capacity - low_watermark))
				return insert_response::full;
		}

		// we primarily want to keep quality nodes in our list.
		// in 15 minutes, any pin-hole the node may have had open to
		// us is likely to have been closed. If the node responds
		// in 15 minutes from now, it's likely to either have a full-cone
		// NAT or not be NATed at all (which is the way we like our nodes).
		// also, it still being up is a good predictor for it staying up
		// longer as well.
		std::uint32_t const expire = duration_cast<seconds>(
			now + minutes(15) - m_created).count();

		m_queue.push_back({addr.to_bytes(), expire, std::uint16_t(sock_idx), port});
		m_ips.insert(addr);
		return insert_response::inserted;
	}

private:

	// this is the type of each node queued up to be pinged at some point in the
	// future
	struct queue_entry_t
	{
		typename Address::bytes_type addr;

		// expiration in seconds (relative to the ping_queue creation time)
		std::uint32_t expire;

		// the index of the socket this node was seen on, and should be pinged
		// back via
		std::uint16_t sock_idx;

		std::uint16_t port;
	};

	// the set of IPs in the queue. An IP is only allowed to appear once
	ip_set<Address> m_ips;

	// the queue of nodes we should ping, ordered by the
	// time they were added
	// TODO: it would be nice to keep the ping queue in a memory mapped file as
	// well
	std::deque<queue_entry_t> m_queue;

	// the total number of queue entries we're allowed to keep
	size_t const m_capacity;

	time_point const m_created;

	// this is a wrapping counter used to determine the probability of dropping
	// this node when the queue is under pressure. It's deliberately meant to
	// wrap at 256.
	std::uint8_t m_round_robin = 0;
};


