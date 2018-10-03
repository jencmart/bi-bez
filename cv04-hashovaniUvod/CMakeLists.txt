cmake_minimum_required(VERSION 3.9)
project(c04)

set(CMAKE_CXX_STANDARD 11)


set(CMAKE_CXX_FLAGS "-lcrypto")
add_executable(c04 main.cpp)
