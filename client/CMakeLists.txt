cmake_minimum_required(VERSION 3.16)
project(client)

ADD_EXECUTABLE(client
    main.cpp
    client.cpp
    client_errors.cpp
)

set_target_properties(client PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(client
    zclp_utils
    zclp++
)

target_include_directories(client
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
