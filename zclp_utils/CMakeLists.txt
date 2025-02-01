cmake_minimum_required(VERSION 3.10)
project(zclp_utils)

add_library(zclp_utils
    zclp_utils.hpp
)

set_target_properties(zclp_utils PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(zclp_utils
    crypto
)

target_include_directories(zclp_utils
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
