cmake_minimum_required(VERSION 2.8)

project(udproxy)

file(GLOB PROJECT_SRC
    "src/*.h"
    "src/*.c"
)
add_executable(${PROJECT_NAME} ${PROJECT_SRC})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} netfilter_queue uv)
