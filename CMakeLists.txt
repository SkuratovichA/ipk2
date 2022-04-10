cmake_minimum_required(VERSION 3.21)
project(ipk)

set(CMAKE_CXX_STANDARD 20)

#include_directories(/usr/local/Cellar/libnet/1.2/include)
#target_link_libraries(ipk "/usr/local/Cellar/libnet/1.2/include")

set(PROJECT_SOURCE_DIR src/)
# give all source files
FILE(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/*.cpp)

add_executable(ipk ${SOURCE_FILES} src/structures.h src/PacketParser.cpp src/PacketParser.h)
target_link_libraries(ipk pcap)
