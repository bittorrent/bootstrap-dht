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

TEST_CASE("mapped_file")
{
	unlink("test_file1");
	{
		mapped_file mf("test_file1", 10 * sizeof(int));
		for (int i = 0; i < 10; ++i) {
			static_cast<int*>(mf.data())[i] = i;
		}
	}

	struct stat st;
	stat("test_file1", &st);
	CHECK(st.st_size == 10 * sizeof(int));

	{
		mapped_file mf("test_file1", 10 * sizeof(int));
		for (int i = 0; i < 10; ++i) {
			CHECK(static_cast<int*>(mf.data())[i] == i);
		}
	}
	unlink("test_file1");
}

