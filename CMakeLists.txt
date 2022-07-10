cmake_minimum_required(VERSION 3.23)
project(pddns)

set(CMAKE_CXX_STANDARD 17)

include(ExternalProject)
set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)
include(cmake/pdargs.cmake)

add_executable(pddns pddns.cpp)

target_include_directories(pddns PRIVATE ${PDARGS_INCLUDE_DIR})
