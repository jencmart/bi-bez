cmake_minimum_required(VERSION 3.9)
project(cv06_obrazek)

set(CMAKE_CXX_STANDARD 11)



ADD_LIBRARY(LibsModule
        main.cpp)


target_link_libraries(LibsModule -lcrypto)


add_executable(cv06_obrazek main.cpp)

target_link_libraries(cv06_obrazek LibsModule)
