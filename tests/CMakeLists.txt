cmake_minimum_required(VERSION 3.10)
project(tests)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

option(BUILD_ACK_FRAME "Build the ack_frame test" OFF)
option(BUILD_CONNECTION_CLOSE_FRAME "Build the connection_close_frame test" OFF)
option(BUILD_CRYPTO_FRAME "Build the crypto_frame test" OFF)
option(BUILD_CLUSTER_MASK_FRAME "Build the cluster_mask_frame test" OFF)
option(BUILD_DATA_BLOCKED_FRAME "Build the data_blocked_frame test" OFF)
option(BUILD_HAND_SHAKE_DONE_FRAME "Build the hand_shake_done_frame test" OFF)
option(BUILD_HEADER_PROTECTION "Build the header_protection test" OFF)
option(BUILD_LONG_HEADER "Build the long_header test" OFF)
option(BUILD_MAX_DATA_FRAME "Build the max_data_frame test" OFF)
option(BUILD_MAX_STREAM_DATA_FRAME "Build the max_stream_data_frame test" OFF)
option(BUILD_MAX_STREAMS_FRAME "Build the max_streams_frame test" OFF)
option(BUILD_NEW_CONNECTION_ID_FRAME "Build the new_connection_id_frame test" OFF)
option(BUILD_NEW_TOKEN_FRAME "Build the new_token_frame test" OFF)
option(BUILD_PADDING_FRAME "Build the padding_frame test" OFF)
option(BUILD_PATH_CHALLENGE_FRAME "Build the path_challange_frame test" OFF)
option(BUILD_PATH_RESPONSE_FRAME "Build the path_response_frame test" OFF)
option(BUILD_PING_FRAME "Build the ping_frame test" OFF)
option(BUILD_PROTECTED_LONG_HEADER "Build the protected_long_header test" OFF)
option(BUILD_RESET_STREAM_FRAME "Build the reset_stream_frame test" OFF)
option(BUILD_RETIRE_CONNECTION_ID_FRAME "Build the retire_connection_id_frame test" OFF)
option(BUILD_SERVER_ASYNC "Build the server_async test" OFF)
option(BUILD_STATELESS_RESET "Build the stateless_reset test" OFF)
option(BUILD_STOP_SENDING_FRAME "Build the stop_sending_frame test" OFF)
option(BUILD_STREAM_DATA_BLOCKED_FRAME "Build the stream_data_blocked_frame test" OFF)
option(BUILD_STREAMS_BLOCKED_FRAME "Build the streams_blocked_frame test" OFF)
option(BUILD_STREAM_FRAME "Build the stream_frame test" OFF)
option(BUILD_VERSION_NEGOTIATION "Build the version_negotiation test" OFF)
option(BUILD_VL_INTEGER "Build the vl_integer test" OFF)

add_subdirectory(../zclp_utils ${CMAKE_BINARY_DIR}/zclp_utils)
add_subdirectory(../zclp++ ${CMAKE_BINARY_DIR}/zclp++)

set(TEST_SOURCES
    ack_frame.cpp
    connection_close_frame.cpp
    crypto_frame.cpp
    cluster_mask_frame.cpp
    data_blocked_frame.cpp
    hand_shake_done_frame.cpp
    header_protection.cpp
    long_header.cpp
    max_data_frame.cpp
    max_stream_data_frame.cpp
    max_streams_frame.cpp
    new_connection_id_frame.cpp
    new_token_frame.cpp
    padding_frame.cpp
    path_challenge_frame.cpp
    path_response_frame.cpp
    ping_frame.cpp
    protected_long_header.cpp
    reset_stream_frame.cpp
    retire_connection_id_frame.cpp
    server_async.cpp
    stateless_reset.cpp
    stop_sending_frame.cpp
    stream_data_blocked_frame.cpp
    streams_blocked_frame.cpp
    stream_frame.cpp
    version_negotiation.cpp
    vl_integer.cpp
)

foreach(TEST_FILE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    string(TOUPPER ${TEST_NAME} TEST_OPTION)
    set(TEST_OPTION "BUILD_${TEST_OPTION}")
    if(${TEST_OPTION})
        add_executable(${TEST_NAME} ${TEST_FILE})
        target_link_libraries(${TEST_NAME}
        zclp_utils
        zclp++
        gtest
        gtest_main
        pthread
        crypto
        )
        set_target_properties(${TEST_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "../bin")
    endif()
endforeach()
