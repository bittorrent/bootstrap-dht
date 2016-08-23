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

#include "node_buffer.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using v4 = boost::asio::ip::address_v4;
using v6 = boost::asio::ip::address_v6;

namespace {
char const* node_id = "aaaaaaaaaaaaaaaaaaaa";
}

TEST_CASE("node_buffer initial state")
{
	unlink("test-node-buffer-1");
	node_buffer<address_v4> buf("test-node-buffer-1", 10);

	CHECK(buf.empty());

	unlink("test-node-buffer-1");
}

template <size_t N>
bool compare(std::array<span<char const>, N> const& ranges, std::string cmp)
{
	for (auto const& r : ranges) {
		if (cmp.substr(0, r.size()) != std::string(r.data(), r.size()))
			return false;
		cmp = cmp.substr(r.size());
	}
	return cmp.empty();
}

TEST_CASE("node_buffer single")
{
	unlink("test-node-buffer-2");
	node_buffer<address_v4> buf("test-node-buffer-2", 10);

	CHECK(compare(buf.get_nodes(1), ""));

	buf.insert_node(v4::from_string("10.1.1.1"), 6881, node_id);

	CHECK(compare(buf.get_nodes(10), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"));

	// since there's only one entry, we should get it back every time we ask
	CHECK(compare(buf.get_nodes(10), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"));

	unlink("test-node-buffer-2");
}

TEST_CASE("node_buffer duplicate")
{
	unlink("test-node-buffer-3");
	node_buffer<address_v4> buf("test-node-buffer-3", 10);

	// make sure we don't allow duplicate IPs in the node buffer
	buf.insert_node(v4::from_string("10.1.1.1"), 6881, node_id);
	buf.insert_node(v4::from_string("10.1.1.1"), 6881, node_id);
	buf.insert_node(v4::from_string("10.1.1.2"), 6881, node_id);

	// asking for nodes should give 10.1.1.2 as many times as 10.1.1.1
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x02\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x02\x1a\xe1"));

	unlink("test-node-buffer-3");
}

TEST_CASE("node_buffer wrap")
{
	unlink("test-node-buffer-4");
	node_buffer<address_v4> buf("test-node-buffer-4", 10);

	// make sure writing nodes exceeding the capacity starts over at the
	// beginning
	for (int i = 0; i < 20; ++i) {
		std::string ip = "10.1.1." + std::to_string(i);
		buf.insert_node(v4::from_string(ip.c_str()), 6881, node_id);
	}

	// asking for nodes, we should only see the last 10 nodes added
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0a\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0b\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0c\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0d\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0e\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0f\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x10\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x11\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x12\x1a\xe1"));
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x13\x1a\xe1"));

	// and then start over again
	CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0a\x1a\xe1"));

	unlink("test-node-buffer-4");
}

TEST_CASE("node_buffer restore")
{
	unlink("test-node-buffer-5");
	{
		node_buffer<address_v4> buf("test-node-buffer-5", 10);

		for (int i = 1; i < 11; ++i) {
			std::string ip = "10.1.1." + std::to_string(i);
			buf.insert_node(v4::from_string(ip.c_str()), 6881, node_id);
		}

		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x02\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x03\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x04\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x05\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x06\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x07\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x08\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x09\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0a\x1a\xe1"));
	}

	{
		node_buffer<address_v4> buf("test-node-buffer-5", 10);

		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x02\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x03\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x04\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x05\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x06\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x07\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x08\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x09\x1a\xe1"));
		CHECK(compare(buf.get_nodes(1), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0a\x1a\xe1"));

		// also make sure the IP unordered set used to prevent duplicates was
		// restored
		// this is a duplicate and should be rejeted
		CHECK(buf.insert_node(v4::from_string("10.1.1.1"), 6881, node_id) == false);

		// this is not a duplicate and should be accepted
		CHECK(buf.insert_node(v4::from_string("10.1.1.11"), 6881, node_id) == true);
	}

	unlink("test-node-buffer-5");
}

TEST_CASE("node_buffer multi-request")
{
	unlink("test-node-buffer-6");
	{
		node_buffer<address_v4> buf("test-node-buffer-6", 10);

		for (int i = 1; i < 11; ++i) {
			std::string ip = "10.1.1." + std::to_string(i);
			buf.insert_node(v4::from_string(ip.c_str()), 6881, node_id);
		}

		CHECK(compare(buf.get_nodes(10), "aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x02\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x03\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x04\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x05\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x06\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x07\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x08\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x09\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0a\x1a\xe1"));
	}

	unlink("test-node-buffer-6");
}

TEST_CASE("node_buffer wrapping-request")
{
	unlink("test-node-buffer-7");
	{
		node_buffer<address_v4> buf("test-node-buffer-7", 10);

		for (int i = 1; i < 11; ++i) {
			std::string ip = "10.1.1." + std::to_string(i);
			buf.insert_node(v4::from_string(ip.c_str()), 6881, node_id);
		}

		// advance the read cursor
		for (int i = 0; i < 5; ++i) {
			buf.get_nodes(1);
		}

		CHECK(compare(buf.get_nodes(9),
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x06\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x07\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x08\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x09\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x0a\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x01\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x02\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x03\x1a\xe1"
			"aaaaaaaaaaaaaaaaaaaa\x0a\x01\x01\x04\x1a\xe1"));
	}

	unlink("test-node-buffer-7");
}
