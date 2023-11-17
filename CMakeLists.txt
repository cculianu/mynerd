
cmake_minimum_required(VERSION 3.17)

project(MyNerd
	VERSION 1.0.0
	DESCRIPTION "A CPU miner written in C++"
	HOMEPAGE_URL "https://www.github.com/cculianu/mynerd"
)

# Package information
set(PACKAGE_NAME "MyNerd")

# Copyright
set(COPYRIGHT_YEAR 2023)
set(COPYRIGHT_HOLDERS "Calin Culianu <calin.culianu@gmail.com>")

# Add path for custom modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

# Default to Release configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Select the configuration for the build" FORCE)
	set(__NO_USER_CMAKE_BUILD_TYPE ON CACHE BOOL "True if the user didn't set a build type on the command line")
endif()

add_subdirectory(src)

