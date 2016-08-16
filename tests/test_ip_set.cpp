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

#include "ip_set.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using v4 = address_v4;
using v6 = address_v6;

TEST_CASE("ip_set IPv4 count")
{
	ip_set<address_v4> set4;
	set4.insert(v4::from_string("127.0.0.1"));

	CHECK(set4.count(v4::from_string("127.0.0.1")) == 1);
	CHECK(set4.count(v4::from_string("127.0.0.2")) == 0);
	CHECK(set4.count(v4::from_string("1.0.0.127")) == 0);
}

TEST_CASE("ip_set IPv4 erase")
{
	ip_set<address_v4> set4;
	set4.insert(v4::from_string("127.0.0.1"));

	CHECK(set4.count(v4::from_string("127.0.0.1")) == 1);
	set4.erase(v4::from_string("127.0.0.1"));
	CHECK(set4.count(v4::from_string("127.0.0.1")) == 0);
}

TEST_CASE("ip_set IPv4 compare equal")
{
	ip_set<address_v4> set4[2];
	set4[0].insert(v4::from_string("127.0.0.1"));
	set4[1].insert(v4::from_string("127.0.0.1"));

	CHECK(set4[0] == set4[1]);
}

TEST_CASE("ip_set IPv4 compare not equal")
{
	ip_set<address_v4> set4[2];
	set4[0].insert(v4::from_string("127.0.0.1"));
	set4[1].insert(v4::from_string("127.0.0.2"));

	CHECK(!(set4[0] == set4[1]));
}

TEST_CASE("ip_set IPv6 count")
{
	ip_set<address_v6> set6;
	set6.insert(v6::from_string("::1"));

	CHECK(set6.count(v6::from_string("::1")) == 1);
	CHECK(set6.count(v6::from_string("ff::2")) == 0);
	CHECK(set6.count(v6::from_string("ff::1")) == 0);
}

TEST_CASE("ip_set IPv6 count prefix")
{
	// we only look at the first 6 bytes of the IPv6 address, make sure
	// subsequent bytes all count as the same IP
	ip_set<address_v6> set6;
	set6.insert(v6::from_string("::1"));

	CHECK(set6.count(v6::from_string("::1")) == 1);
	CHECK(set6.count(v6::from_string("::2")) == 1);
	CHECK(set6.count(v6::from_string("::1")) == 1);
	CHECK(set6.count(v6::from_string("0000:0000:0000:ff::")) == 1);
	CHECK(set6.count(v6::from_string("0000:0000:000f:ff::")) == 0);
}

TEST_CASE("ip_set IPv6 erase")
{
	ip_set<address_v6> set6;
	set6.insert(v6::from_string("::1"));

	CHECK(set6.count(v6::from_string("::1")) == 1);
	set6.erase(v6::from_string("::1"));
	CHECK(set6.count(v6::from_string("::1")) == 0);
}

TEST_CASE("ip_set IPv6 compare equal")
{
	ip_set<address_v6> set6[2];
	set6[0].insert(v6::from_string("::1"));
	set6[1].insert(v6::from_string("::1"));

	CHECK(set6[0] == set6[1]);
}

TEST_CASE("ip_set IPv6 compare not equal")
{
	ip_set<address_v6> set6[2];
	set6[0].insert(v6::from_string("::1"));
	set6[1].insert(v6::from_string("ff::1"));

	CHECK(!(set6[0] == set6[1]));
}

TEST_CASE("extract_key IPv6")
{
	ipv6_prefix_type expect{{ 1, 2, 3, 4, 5, 6}};
	CHECK(extract_key(v6::from_string("0102:0304:0506::")) == expect);
}

