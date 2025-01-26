add_executable(spoofy 
        utils/rand.cpp
        jsonbuilder.cpp
        sniffer.cpp
        spoofer.cpp
        sender.cpp
        app.cpp
        main.cpp
)

set_target_properties(spoofy
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )

find_package(Threads REQUIRED)

if(WIN32)
    target_link_libraries(spoofy 
        PRIVATE cclap 
        PRIVATE tins 
        PRIVATE rdkafka++ 
        PRIVATE Threads::Threads 
        PRIVATE Ws2_32 PRIVATE Iphlpapi PRIVATE ${PCAP_ROOT_DIR}/Lib/wpcap.lib)
    target_include_directories(spoofy 
        PRIVATE ${CMAKE_SOURCE_DIR}/include 
        PRIVATE ${cclap_SOURCE_DIR}/include 
        PRIVATE ${libtins_SOURCE_DIR}/include 
        PRIVATE ${rapidjson_SOURCE_DIR}/include
        PRIVATE ${PCAP_ROOT_DIR}/Include)
    target_compile_definitions(spoofy PRIVATE WIN32 PRIVATE TINS_STATIC)
else()
    target_link_libraries(spoofy 
        PRIVATE cclap 
        PRIVATE tins 
        PRIVATE rdkafka++ 
        PRIVATE Threads::Threads)
    target_include_directories(spoofy 
        PRIVATE ${CMAKE_SOURCE_DIR}/include 
        PRIVATE ${cclap_SOURCE_DIR}/include 
        PRIVATE ${libtins_SOURCE_DIR}/include
        PRIVATE ${rapidjson_SOURCE_DIR}/include) # add this once we online
        #        PRIVATE ${CMAKE_SOURCE_DIR}/build/_deps/rapidjson-src/include)
endif()


