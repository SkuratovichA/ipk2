cmake_minimum_required(VERSION 3.21)
project(ipk_sniffer)

set(CMAKE_CXX_STANDARD 20)

set(PROJECT_SOURCE_DIR src/)
# give all source files
FILE(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/*.cpp)

add_executable(ipk_sniffer ${SOURCE_FILES} src/structures.h)
target_link_libraries(ipk_sniffer pcap)
