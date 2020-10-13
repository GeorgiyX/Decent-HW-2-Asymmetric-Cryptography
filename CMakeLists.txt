cmake_minimum_required(VERSION 3.16.3)
project(hw2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")

include_directories(project/include)

add_executable(HW_2 project/src/main.cpp project/include/utils.h project/src/utils.cpp)