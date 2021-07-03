cmake_minimum_required(VERSION 3.19)
project(scan_util)

set(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_FLAGS -pthread)

add_executable(scan_util main.cpp)