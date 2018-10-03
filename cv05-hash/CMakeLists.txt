cmake_minimum_required(VERSION 3.9)
project(cv05_hash)

set(CMAKE_CXX_STANDARD 11)

ADD_LIBRARY(LibsModule
        main.cpp)


target_link_libraries(LibsModule -lcrypto)

add_executable(cv05_hash main.cpp)

target_link_libraries(cv05_hash LibsModule)
