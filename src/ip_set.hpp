/*
The MIT License (MIT)

Copyright (c) 2013-2014 BitTorrent Inc.
Copyright (c) 2016 Arvid Norberg

author: Arvid Norberg & Steven Siloti

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

#include <unordered_set>
#include <cstdint>
#include <array>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include "city.h"

// The size of ipv6_prefix_type determines the size of the prefix to compare
// when determining if an IPv6 address should be discarded as a duplicate
using ipv6_prefix_type = std::array<std::uint8_t, 6>;

using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;

extern std::uint64_t hash_seed;

template <typename T, typename K>
void erase_one(T& container, K const& key)
{
	typename T::iterator i = container.find(key);
	assert(i != container.end());
	container.erase(i);
}

inline ipv6_prefix_type extract_key(address_v6 const& addr)
{
	ipv6_prefix_type ip6;
	std::memcpy(ip6.data(), addr.to_bytes().data(), ip6.size());
	return ip6;
}

inline address_v4::bytes_type extract_key(address_v4 const& addr)
{
	return addr.to_bytes();
}

namespace std {

template <>
struct hash<address_v4::bytes_type>
{
	size_t operator()(address_v4::bytes_type ip) const
	{
		return CityHash64WithSeed(reinterpret_cast<char const*>(&ip[0]), ip.size(), hash_seed);
	}
};

template <>
struct hash<ipv6_prefix_type>
{
	size_t operator()(ipv6_prefix_type const ip) const
	{
		return CityHash64WithSeed(reinterpret_cast<char const*>(&ip[0]), ip.size(), hash_seed);
	}
};

} // namespace std

template <typename Address>
struct ip_set
{
	// returns true if the address was not already in the set
	bool insert(Address const& addr)
	{ return m_ips.insert(extract_key(addr)).second; }

	size_t count(Address const& addr) const
	{ return m_ips.count(extract_key(addr)); }

	void erase(Address const& addr)
	{ erase_one(m_ips, extract_key(addr)); }

	bool operator==(ip_set const& rh) const
	{ return m_ips == rh.m_ips; }

	size_t size() const { return m_ips.size(); }
	void clear() { m_ips.clear(); }

private:
	std::unordered_set<decltype(extract_key(std::declval<Address>()))> m_ips;
};

