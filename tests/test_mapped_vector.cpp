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

#include "mapped_file.hpp"
#include <sys/stat.h>
#include <unistd.h> // for unlink

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("mapped_vector")
{
	unlink("test_file2");
	{
		mapped_vector<int> mv("test_file2", 30);
		CHECK(mv.size() == 0);
		CHECK(mv.capacity() == 30);

		for (int i = 0; i < 10; ++i) {
			mv.emplace_back(i);
		}

		CHECK(mv.size() == 10);
	}

	{
		// make sure the size of the vector (not the capacity) is correctly
		// restored when loading it back up again
		mapped_vector<int> mv("test_file2", 30);
		CHECK(mv.size() == 10);
		CHECK(mv.capacity() == 30);
		for (int i = 0; i < 10; ++i) {
			CHECK(mv[i] == i);
		}
	}

	// make sure the size is capped at the capacity, if the capacity is shrunk
	{
		mapped_vector<int> mv("test_file2", 5);
		CHECK(mv.size() == 5);
		CHECK(mv.capacity() == 5);
	}

	unlink("test_file2");
}


