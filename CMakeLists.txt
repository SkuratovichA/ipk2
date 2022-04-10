cmake_minimum_required(VERSION 3.17)
project (ipk)

set(CMAKE_CXX_STANDARD 17)

#include_directories(/usr/local/Cellar/libnet/1.2/include)
#target_link_libraries(ipk "/usr/local/Cellar/libnet/1.2/include")

set(PROJECT_SOURCE_DIR src/)
# give all source files
FILE(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/*.cpp)

add_executable(ipk ${SOURCE_FILES})
target_link_libraries(ipk pcap)
#target_link_libraries(ipk net)

#
#cmake_minimum_required(VERSION 3.17)
#project (ipk)
#
#set(CMAKE_CXX_STANDARD 17)
#
##include_directories(/usr/local/Cellar/libnet/1.2/include)
##target_link_libraries(ipk "/usr/local/Cellar/libnet/1.2/include")
#
#set(PROJECT_SOURCE_DIR src/)
#
#set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH})
## give all source files
#FILE(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/*.cpp)
#add_executable(ipk ${SOURCE_FILES})
#target_link_libraries(ipk ${PCAP_LIBRARY})
