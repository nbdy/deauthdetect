cmake_minimum_required(VERSION 3.10)
project(deauthdetect)

set(CMAKE_CXX_STANDARD 11)

add_executable(deauthdetect main.cpp)
target_link_libraries(deauthdetect tins)