cmake_minimum_required(VERSION 3.10)
project(cv10_certifikaty)

set(CMAKE_CXX_STANDARD 11)


ADD_LIBRARY(LibsModule
        main.cpp)


target_link_libraries(LibsModule -lcrypto -lssl)


add_executable(cv10_certifikaty main.cpp)


target_link_libraries(cv10_certifikaty LibsModule)
