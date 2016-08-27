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

#include <array>
#include <algorithm>
#include <chrono>
#include "ip_set.hpp"
#include "mapped_file.hpp" // for mapped_vector
#include "span.hpp"

template <typename Address>
struct node_buffer
{
	using address_type = Address;
	using steady_clock = std::chrono::steady_clock;
	using node_id_type = std::array<char, 20>;

	// this is the type of each node entry
	// in the circular buffer
	struct node_entry_t
	{
		node_id_type node_id;
		typename Address::bytes_type ip;
		uint16_t port;
	};

	node_buffer(char const* filename, size_t const capacity)
		: m_current_max_size(std::min(size_t(99), capacity))
		, m_capacity(capacity)
		, m_last_write_loop(steady_clock::now())
		, m_buffer(filename, capacity)
	{
		// if we picked up nodes from the previous session, we need to restore our
		// set of IPs too (used to disallow duplicates) as well as making sure the
		// current_max_size and write cursors are set correctly
		if (m_buffer.size() > 0) {
			for (node_entry_t const& e : m_buffer) {
				m_ips.insert(address_type(e.ip));
			}
			m_write_cursor = m_buffer.size();
			if (m_current_max_size < m_buffer.size()) {
				m_current_max_size = m_buffer.size();
			}
			if (m_write_cursor >= m_current_max_size) {
				m_write_cursor = 0;
			}
		}
	}

	bool empty() const { return m_buffer.empty(); }

	int size() const { return m_current_max_size; }

	// returns two spans containing the peer IP, port and node IDs. The second
	// span may be empty.
	std::array<span<char const>, 2>
	get_nodes(int const num_nodes)
	{
		if (m_buffer.size() <= num_nodes)
		{
			// this is the case where we have fewer nodes in the node_buffer than
			// we want to send in a single response
			m_read_cursor = 0;
			return {{
				{reinterpret_cast<char const*>(m_buffer.data()), m_buffer.size() * sizeof(node_entry_t)}
				, {}}};
		}

		if (m_read_cursor == m_buffer.size())
			m_read_cursor = 0;

		if (m_read_cursor <= m_buffer.size() - num_nodes)
		{
			// this is the common case, where we have sufficient nodes ahead of the
			// read cursor to just return a single range
			std::array<span<char const>, 2> const ret{{
				{reinterpret_cast<char const*>(&m_buffer[m_read_cursor]), num_nodes * sizeof(node_entry_t)}
				, {}}};
			m_read_cursor += num_nodes;
			return ret;
		}

		size_t const slice1 = m_buffer.size() - m_read_cursor;
		assert(slice1 < num_nodes);
		size_t const slice2 = num_nodes - slice1;

		std::array<span<char const>, 2> const ret{{
			{reinterpret_cast<char const*>(&m_buffer[m_read_cursor]), slice1 * sizeof(node_entry_t)}
			, {reinterpret_cast<char const*>(&m_buffer[0]), slice2 * sizeof(node_entry_t)}
		}};
		m_read_cursor = slice2;
		assert(slice1 + slice2 == num_nodes);
		return ret;
	}

	// returns whether the node was inserted or not
	bool insert_node(address_type const& addr, uint16_t port, char const* node_id)
	{
		using std::chrono::minutes;

		node_entry_t e;
		e.ip = addr.to_bytes();
		e.port = htons(port);
		memcpy(e.node_id.data(), node_id, e.node_id.size());

		// we're not supposed to add 0.0.0.0
		assert(!addr.is_unspecified());

		// only allow one entry per IP
		if (m_ips.count(address_type(e.ip))) return false;

		auto const now = steady_clock::now();
		if (m_write_cursor == m_current_max_size
			&& m_last_write_loop + minutes(15) > now)
		{
			// we're about to wrap the write cursor, but it's been less
			// than 15 minutes since last time we wrapped, so extend
			// the buffer
			m_current_max_size = (std::min)(m_current_max_size * 2, m_capacity);
		}

		// this test must be here even though it's also tested
		// in the above if-statement. If we try to grow the buffer
		// size, we may still be stuck at the upper limit, in which
		// case we still need to wrap
		if (m_write_cursor == m_current_max_size)
		{
#ifdef DEBUG_STATS
			printf("write cursor wrapping. %d minutes\n"
				, int(std::chrono::duration_cast<minutes>(now - m_last_write_loop).count()));
#endif
			m_write_cursor = 0;
			m_last_write_loop = now;
		}

		if (m_buffer.size() < m_current_max_size)
		{
			m_buffer.emplace_back(e);
			m_ips.insert(address_type(e.ip));
			++m_write_cursor;
			return true;
		}

		// remove the IP we're overwriting from our IP set
		m_ips.erase(address_type(m_buffer[m_write_cursor].ip));
		m_buffer[m_write_cursor] = e;
		// and add the one we just put in
		m_ips.insert(address_type(e.ip));
		++m_write_cursor;
		return true;
	}

private:

	size_t m_read_cursor = 0;
	size_t m_write_cursor = 0;

	// the current max size we use for the node buffer. If it's churning too
	// frequently, we grow it
	int m_current_max_size;

	int const m_capacity;

	// the last time we looped the write cursor. If this is less than 15 minutes
	// we double the size of the buffer (capped at the specified size)
	steady_clock::time_point m_last_write_loop;

	mapped_vector<node_entry_t> m_buffer;

	// this is a set of all IPs that's currently in the buffer. We only allow
	// one instance of each IP
	ip_set<address_type> m_ips;
};

