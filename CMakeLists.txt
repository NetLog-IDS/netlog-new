cmake_minimum_required(VERSION 3.11)
project(spoofy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
endif(CCACHE_FOUND)

IF(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Setting build type to 'RelWithDebInfo'.")
    SET(CMAKE_BUILD_TYPE RelWithDebInfo)
ELSE(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Using specified '${CMAKE_BUILD_TYPE}' build type.")
ENDIF(NOT CMAKE_BUILD_TYPE)

include(FetchContent)
FetchContent_Declare(
    cclap
    GIT_REPOSITORY    https://github.com/adriancostin6/cclap.git
    )
FetchContent_Declare(
    libtins
    GIT_REPOSITORY    https://github.com/mfontanini/libtins.git
    )
FetchContent_Declare(
    librdkafka
    GIT_REPOSITORY    https://github.com/edenhill/librdkafka.git
    )
FetchContent_Declare(
    rapidjson
    GIT_REPOSITORY   https://github.com/Tencent/rapidjson.git
    )

if (SPOOFY_FETCH_DEPS)
    message(STATUS "Fetching cclap...")
    FetchContent_MakeAvailable(cclap)
    message(STATUS "Fetching libtins...")
    FetchContent_MakeAvailable(libtins)
    message(STATUS "Fetching librdkafka...")
    FetchContent_MakeAvailable(librdkafka)
    message(STATUS "Fetching rapidjson...")
    FetchContent_MakeAvailable(rapidjson)
endif()


if (SPOOFY_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        catch2
        GIT_REPOSITORY    https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.0.0-preview4
        )
    message(STATUS "Fetching Catch2...")
    FetchContent_MakeAvailable(catch2)

    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include (CTest)
    include (Catch)
endif()

add_subdirectory(src)
