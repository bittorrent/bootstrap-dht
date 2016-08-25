/*
The MIT License (MIT)

Copyright (c) 2013 BitTorrent Inc.

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

#ifndef _BENCODE_HPP_
#define _BENCODE_HPP_

#include <cstring>
#include <string>
#include <algorithm>
#include <array>

#include "span.hpp"

struct bencoder
{
	bencoder(char* buf, int len) : m_buf(buf), m_end(buf + len) {}

	void open_dict() { if (m_buf < m_end) *m_buf++ = 'd'; }
	void close_dict() { if (m_buf < m_end) *m_buf++ = 'e'; }
	void open_list() { if (m_buf < m_end) *m_buf++ = 'l'; }
	void close_list() { if (m_buf < m_end) *m_buf++ = 'e'; }
	void add_string(char const* str, size_t len)
	{
		m_buf += std::snprintf(m_buf, m_end - m_buf, "%zu:", len);
		len = (std::min)(len, size_t(m_end - m_buf));
		memcpy(m_buf, str, len);
		m_buf += len;
	}
	void add_string(char const* str)
	{
		size_t len = std::strlen(str);
		add_string(str, len);
	}
	void add_string(span<char> str)
	{
		add_string(str.data(), str.size());
	}

	template <size_t N>
	void add_string_concatenate(std::array<span<char const>, N> const& ranges)
	{
		size_t len = 0;
		for (auto const& r : ranges) len += r.size();

		m_buf += std::snprintf(m_buf, m_end - m_buf, "%zu:", len);

		if (m_end - m_buf < len) return;

		for (auto const& r : ranges) {
			if (r.empty()) continue;
			memcpy(m_buf, r.data(), r.size());
			m_buf += r.size();
		}
	}
	char* end() const { return m_buf; }

private:

	char* m_buf;
	char* m_end;
};

#endif

