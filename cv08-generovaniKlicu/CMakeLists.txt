cmake_minimum_required(VERSION 3.10)
project(cv08_generovaniKlicu)

set(CMAKE_CXX_STANDARD 11)


ADD_LIBRARY(LibsModule
        main.cpp)


target_link_libraries(LibsModule -lcrypto)


add_executable(cv08_generovaniKlicu main.cpp)


target_link_libraries(cv08_generovaniKlicu LibsModule)
