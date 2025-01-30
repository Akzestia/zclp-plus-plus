cmake_minimum_required(VERSION 3.10)
project(zclp++)

option(BUILD_CLIENT "Build the client" OFF)
option(BUILD_SERVER "Build the server" OFF)

if(BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(BUILD_SERVER)
    add_subdirectory(server)
endif()
