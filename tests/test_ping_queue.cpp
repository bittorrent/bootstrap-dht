/*
The MIT License (MIT)

Copyright (c) 2016 Arvid Norberg

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

#include "ping_queue.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using v4 = boost::asio::ip::address_v4;
using v6 = boost::asio::ip::address_v6;

using steady_clock = std::chrono::steady_clock;
using time_point = steady_clock::time_point;

TEST_CASE("ping_queue initial state")
{
	time_point const start = steady_clock::now();
	ping_queue<address_v4> q(32, start);

	CHECK(q.size() == 0);

	queued_node_t n;
	CHECK(q.need_ping(&n, start) == false);
	CHECK(q.need_ping(&n, start) == false);
}

TEST_CASE("ping_queue overrun")
{
	time_point const start = steady_clock::now();

	ping_queue<address_v4> q(32, start);

	CHECK(q.insert_node(v4::from_string("1.2.3.4"), 6881, 0, start) == insert_response::inserted);
	CHECK(q.size() == 1);
	CHECK(q.insert_node(v4::from_string("1.2.3.5"), 6881, 0, start) == insert_response::inserted);
	CHECK(q.size() == 2);

	int added = 2;
	for (int i = 0; i < 64; ++i) {
		added += (q.insert_node(v4::from_string("1.2.4." + std::to_string(i)), 6881, 0, start) == insert_response::inserted);
	}
	// despite adding 66 nodes, we should not have exceeded our capacity
	CHECK(q.size() <= 32);
	// the low watermark, the level before we start dropping nodes, should have
	// been satisfied at least
	CHECK(q.size() > 16);

	CHECK(q.size() == added);
}

TEST_CASE("ping_queue duplicate")
{
	time_point const start = steady_clock::now();

	ping_queue<address_v4> q(32, start);

	CHECK(q.insert_node(v4::from_string("1.2.3.4"), 6881, 0, start) == insert_response::inserted);
	CHECK(q.size() == 1);

	// duplicates are not allowed
	CHECK(q.insert_node(v4::from_string("1.2.3.4"), 6881, 0, start) == insert_response::duplicate);
	CHECK(q.size() == 1);

	// however, once we pop it, we can queue it up again
	queued_node_t n;
	CHECK(q.need_ping(&n, start + minutes(15) + seconds(1)) == true);
	CHECK(n.ep == udp::endpoint(v4::from_string("1.2.3.4"), 6881));
	CHECK(n.sock_idx == 0);
	CHECK(q.size() == 0);

	CHECK(q.insert_node(v4::from_string("1.2.3.4"), 6881, 0, start) == insert_response::inserted);
	CHECK(q.size() == 1);
}

TEST_CASE("ping_queue expire")
{
	time_point const start = steady_clock::now();

	ping_queue<address_v4> q(32, start);

	CHECK(q.insert_node(v4::from_string("1.2.3.4"), 6881, 0, start) == insert_response::inserted);
	CHECK(q.size() == 1);

	// 14 minutes and 58 seconds later, we still should not ping the node
	queued_node_t n;
	CHECK(q.need_ping(&n, start + minutes(14) + seconds(58)) == false);

	// however, 15 minutes and 1 second later, we _should_ ping it
	CHECK(q.need_ping(&n, start + minutes(15) + seconds(1)) == true);

	CHECK(n.ep == udp::endpoint(v4::from_string("1.2.3.4"), 6881));
	CHECK(n.sock_idx == 0);

	CHECK(q.size() == 0);

	// once we've popped it, there aren't any more entries
	CHECK(q.need_ping(&n, start + minutes(15) + seconds(1)) == false);
}

