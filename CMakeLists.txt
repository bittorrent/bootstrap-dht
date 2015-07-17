cmake_minimum_required(VERSION 2.8)
project(bootstrap-dht)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -Werror ${CMAKE_CXX_FLAGS}")

find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

set(SOURCES main.cpp lazy_bdecode.cpp)
set(HEADERS bencode.hpp lazy_entry.hpp)

include_directories(
    ${CMAKE_BINARY_DIR}/include
    ${Boost_INCLUDE_DIRS})

add_executable(bootstrap-dht ${SOURCES} ${HEADERS})

target_link_libraries(bootstrap-dht
    ${Boost_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT})
