cmake_minimum_required(VERSION 3.0.0)
project(Sniffer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDART 11)
set(CMAKE_CXX_STANDART_REQUIRED ON)

include_directories(headers)

set(PROJECT_MAIN src/main.cpp)
set(PROJECT_SOURCES src/sniffer.cpp)

include(FindPCAP.cmake)

add_executable(Sniffer ${PROJECT_MAIN} ${PROJECT_SOURCES})
target_link_libraries(Sniffer ${PCAP_LIBRARY})

