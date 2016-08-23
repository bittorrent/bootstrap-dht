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

#include <fcntl.h> // for open
#include <sys/mman.h> // for mmap
#include <errno.h>
#include <system_error>
#include <cassert>
#include <unistd.h> // for open/close
#include <cstring> // for memcpy

#include <sys/mman.h> // for madvise

struct file
{
	file(char const* name)
	{
		m_fd = open(name, O_CREAT | O_RDWR, 0700);
		if (m_fd < 0) {
			throw std::system_error(std::error_code(errno, std::generic_category()));
		}
	}
	file(file const&) = delete;
	file& operator=(file const&) = delete;

	int fd() const { return m_fd; }

	~file() { close(m_fd); }

private:
	int m_fd;
};

struct mapped_file
{
	mapped_file(char const* file, size_t const size)
		: m_file(file)
		, m_buf(nullptr)
		, m_size(size)
	{
		if (ftruncate(m_file.fd(), m_size) < 0) {
			throw std::system_error(std::error_code(errno, std::generic_category()));
		}
		m_buf = mmap(nullptr, m_size
			, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, m_file.fd(), 0);
		if (m_buf == MAP_FAILED) {
			throw std::system_error(std::error_code(errno, std::generic_category()));
		}

#if defined MADV_DONTDUMP
		madvise(m_buf, m_size, MADV_DONTDUMP);
#elif defined MADV_NOCORE
		madvise(m_buf, m_size, MADV_NOCORE);
#endif
	}
	mapped_file(mapped_file const&) = delete;
	mapped_file& operator=(mapped_file const&) = delete;

	void* data() { return m_buf; }
	void const* data() const { return m_buf; }
	size_t size() const { return m_size; }

	~mapped_file() { munmap(m_buf, m_size); }

private:

	file m_file;
	void* m_buf;
	size_t const m_size;
};

template <typename T>
struct mapped_vector
{
	// the header must be large enough to make the first element still be
	// correctly aligned
	static constexpr size_t header_size = (16 < alignof(T)) ? alignof(T) : 16;

	mapped_vector(char const* file, size_t const size)
		: m_map(file, header_size + size * sizeof(T))
		, m_size(*static_cast<size_t*>(m_map.data()))
	{
		// the actual array starts immediately after the header
		m_array = reinterpret_cast<T*>(static_cast<char*>(m_map.data()) + header_size);

		// Make sure to cap the size of the vector within its capacity
		if (m_size > capacity()) m_size = capacity();
	}

	void resize(size_t const s)
	{
		if (s == m_size) return;
		if (s < m_size) {
			for (; m_size > s; --m_size) {
				m_array[m_size-1].~T();
			}
		}
		else if (s > capacity()) {
			throw std::range_error("mapped_vector::resize() exceed capacity");
		}
		else {
			for (; m_size < s; ++m_size) {
				new (&m_array[m_size]) T();
			}
		}
	}
	bool empty() const { return m_size == 0; }

	T* data() { return m_array; }
	T const* data() const { return m_array; }
	size_t size() const { return m_size; }
	size_t capacity() const { return (m_map.size() - header_size) / sizeof(T); }

	T* begin() { return m_array; }
	T const* begin() const { return m_array; }
	T* end() { return m_array + m_size; }
	T const* end() const { return m_array + m_size; }

	template<typename... Args>
	void emplace_back(Args... args)
	{
		if (m_size >= capacity()) throw std::range_error("mapped_vector::emplace_back() full");

		new (&m_array[m_size]) T(std::forward<Args>(args)...);
		++m_size;
	}

	T& operator[](int const idx)
	{
		assert(idx < m_size);
		assert(idx >= 0);
		return m_array[idx];
	}

	T const& operator[](int const idx) const
	{
		assert(idx < m_size);
		assert(idx >= 0);
		return m_array[idx];
	}

private:
	mapped_file m_map;
	T* m_array;
	// number of items in use, not capacity. This points into the header of the
	// mapped file
	size_t& m_size;
};

