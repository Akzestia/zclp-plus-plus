cmake_minimum_required(VERSION 3.16)
project(stream_manager)

add_library(stream_manager
    stream_manager.h stream_manager.cpp
)

set_target_properties(stream_manager PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(stream_manager
    pthread
)

target_include_directories(stream_manager
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
