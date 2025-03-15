cmake_minimum_required(VERSION 3.16)
project(zclp++)

add_library(zclp++
    zclp++.h zclp++.cpp
)

set_target_properties(zclp++ PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(zclp++
    crypto
    zclp_utils
)

target_include_directories(zclp++
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
