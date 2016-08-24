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


#pragma once

#include <string>
#include <array>

// TODO: at some point it probably makes sense to pull in GSL's span instead
template <typename T>
struct span
{
	using iterator = T*;
	using const_iterator = T const*;

	span() : m_begin(nullptr), m_end(nullptr) {}
	span(T* begin, size_t s) : m_begin(begin), m_end(m_begin + s) {}
	span(std::basic_string<T>& str) : m_begin(&str[0]), m_end(&str[0] + str.size()) {}
	template<size_t N>
	span(std::array<T, N>& arr) : m_begin(arr.data()), m_end(arr.data() + arr.size()) {}
	template<size_t N>
	span(T (&arr)[N]) : m_begin(arr), m_end(arr + N) {}

	T* data() { return m_begin; }
	T const* data() const { return m_begin; }
	size_t size() const { return m_end - m_begin; }
	bool empty() const { return m_begin == m_end; }

	iterator begin() { return m_begin; }
	iterator end() { return m_end; }
	const_iterator begin() const { return m_begin; }
	const_iterator end() const { return m_end; }
private:
	T* m_begin;
	T* m_end;
};

template <typename T, size_t N>
bool operator==(std::array<T, N> const& lhs, span<T> const& rhs)
{
	return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

template <typename T, size_t N>
bool operator==(span<T> lhs, std::array<T, N> const& rhs)
{
	return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

