cmake_minimum_required(VERSION 3.16)
project(server)

ADD_EXECUTABLE(server
    main.cpp
    server.cpp
    server_errors.cpp
)

set_target_properties(server PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(server
    zclp_utils
    zclp++
)

target_include_directories(server
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
