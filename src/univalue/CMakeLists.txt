# Copyright (c) 2017 The Bitcoin developers

cmake_minimum_required(VERSION 3.13)
project(univalue)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(univalue
	lib/univalue.cpp
	lib/univalue_get.cpp
	lib/univalue_read.cpp
	lib/univalue_write.cpp
)

target_include_directories(univalue
	PUBLIC
		include
	PRIVATE
		lib
)
