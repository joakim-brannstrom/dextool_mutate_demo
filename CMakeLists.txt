cmake_minimum_required(VERSION 3.9)
project(readerwriterqueue VERSION 1.0.0)

include(GNUInstallDirs)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(readerwriterqueue INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

install(FILES atomicops.h readerwriterqueue.h readerwritercircularbuffer.h LICENSE.md
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

add_library(simplethread tests/common/simplethread.cpp)
target_compile_options(simplethread PUBLIC "-O3" "-pthread" "-Wl,--no-as-needed")
target_compile_definitions(simplethread PUBLIC "-DNDEBUG")
target_link_libraries(simplethread PUBLIC readerwriterqueue "-lrt" "-lpthread")
target_include_directories(simplethread PUBLIC tests/common)

add_executable(unittests tests/unittests/unittests.cpp)
target_link_libraries(unittests PRIVATE simplethread)

#add_executable(stabtest tests/stabtest/stabtest.cpp)
#target_link_libraries(stabtest PRIVATE simplethread)
