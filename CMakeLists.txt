cmake_minimum_required(VERSION 3.16)

set(CMAKE_GENERATOR_PLATFORM win32)

project(my_tb_plugin)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT(CMAKE_SIZEOF_VOID_P EQUAL 4))
    message(FATAL_ERROR "You are configuring a non 32-bit build, this is not supported. Run cmake with `-A Win32`")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/")

add_compile_options(/MP /permissive-)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_path(SIMPLEINI_INCLUDE_DIRS "ConvertUTF.c")
find_path(EARCUT_HPP_INCLUDE_DIRS "mapbox/earcut.hpp")
find_package(unofficial-uwebsockets CONFIG REQUIRED)
find_package(wolfssl CONFIG REQUIRED)
find_package(minhook CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(ctre CONFIG REQUIRED)
find_package(directxtex CONFIG REQUIRED)

add_compile_definitions(WOLFSSL_NO_OPTIONS_H)
include(gwtoolboxpp)

add_library(my_tb_plugin SHARED)

file(GLOB SOURCES
	"src/*.h"
	"src/*.cpp"
	${gwtoolboxpp_SOURCE_DIR}/plugins/Base/*.h
	${gwtoolboxpp_SOURCE_DIR}/plugins/Base/*.cpp
	)

target_include_directories(my_tb_plugin PRIVATE
	${gwtoolboxpp_SOURCE_DIR}/plugins/Base
	${gwtoolboxpp_SOURCE_DIR}/GWToolboxdll
	${gwtoolboxpp_SOURCE_DIR}/Dependencies/GWCA/include
	${SIMPLEINI_INCLUDE_DIRS}
	)
target_link_libraries(my_tb_plugin PRIVATE
	RestClient
	imgui
	directxtex
	gwca
	easywsclient
	nlohmann_json::nlohmann_json
	wolfssl::wolfssl
	minhook::minhook
	ctre::ctre
	imgui::fonts
	IconFontCppHeaders
	nativefiledialog
	wintoast
	)
target_link_options(my_tb_plugin PRIVATE
	"$<$<CONFIG:DEBUG>:/NODEFAULTLIB:LIBCMT>"
	)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${SOURCES})
target_sources(my_tb_plugin PRIVATE ${SOURCES})
target_compile_definitions(my_tb_plugin PRIVATE
	"NOMINMAX"
	"_WIN32_WINNT=_WIN32_WINNT_WIN7"
	"WIN32_LEAN_AND_MEAN"
	"VC_EXTRALEAN"
	"BUILD_DLL"
	)
set_target_properties(my_tb_plugin PROPERTIES DEBUG_POSTFIX "d")