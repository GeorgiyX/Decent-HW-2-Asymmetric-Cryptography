cmake_minimum_required(VERSION 3.16.3)
project(hw2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")

include_directories(project/include)
find_package(OpenSSL REQUIRED)

add_executable(hw-2 project/src/main.cpp project/include/logic.h project/src/logic.cpp project/src/crypto.cpp project/include/crypto.h)
target_link_libraries(hw-2 OpenSSL::Crypto)