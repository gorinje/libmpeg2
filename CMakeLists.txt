cmake_minimum_required(VERSION 3.7)
project(Filters)

include(filters.cmake)

add_definitions(-fpic)

SET(FILTER_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/dec_libmpeg2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/reframe_mpgvid.c
        ${CMAKE_CURRENT_SOURCE_DIR}/dmx_mpegps.c
        ${CMAKE_CURRENT_SOURCE_DIR}/av_parsers.c
        ${CMAKE_CURRENT_SOURCE_DIR}/media_import.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mpeg2_ps.c
)

SET(FILTER_LIB
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libmpeg2.a
)

SET(FILTER_INC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_filter(libmpeg2
        "${FILTER_SRC}"
        "${FILTER_LIB}"
        []
        ""
        "${FILTER_INC}"
        ""
        "1")
