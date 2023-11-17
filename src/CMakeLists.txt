project(mynerd)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default visibility is hidden on all targets.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

option(ENABLE_STATIC_LIBGCC "Statically link libgcc" OFF)
option(ENABLE_STATIC_LIBSTDCXX "Statically link libstdc++" OFF)

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
  message(STATUS "Using ccache: ${CCACHE}")
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif(CCACHE)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(AddCompilerFlags)

# Ensure assert() works in all modes
remove_compiler_flags(-DNDEBUG)

# Prefer -g3, defaults to -g if unavailable
foreach(LANGUAGE C CXX)
  set(COMPILER_DEBUG_LEVEL -g)
  check_compiler_flags(G3_IS_SUPPORTED ${LANGUAGE} -g3)
  if(${G3_IS_SUPPORTED})
    set(COMPILER_DEBUG_LEVEL -g3)
  endif()
  add_compile_options_to_configuration_for_language(Debug ${LANGUAGE} ${COMPILER_DEBUG_LEVEL})
endforeach()

# Windows specific flags
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  # Ensure that WINDRES_PREPROC is enabled when using windres.
  list(APPEND CMAKE_RC_FLAGS "-DWINDRES_PREPROC")

  # Build all static so there is no dll file to distribute.
  add_linker_flags(-static)

  # _WIN32_WINNT_WIN7
  add_compile_definitions(_WIN32_WINNT=0x0601)
  add_compile_definitions(WINDOWS=1)
elseif(UNIX)
  add_compile_definitions(UNIX=1)
endif()

# OSX specific flags
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_compile_definitions(MAC_OSX OBJC_OLD_DISPATCH_PROTOTYPES=0)
  add_linker_flags(-Wl,-dead_strip_dylibs)
endif()

# Enable statically linking libgcc
if(ENABLE_STATIC_LIBGCC)
  add_linker_flags(-static-libgcc)
endif()

# Enable statically linking libstdc++
if(ENABLE_STATIC_LIBSTDCXX)
  add_linker_flags(-static-libstdc++)
endif()


# libtool style configure
add_subdirectory(config)

# Enable LFS (Large File Support) on targets that don't have it natively.
# This should be defined before the libraries are included as leveldb need the
# definition to be set.
if(NOT HAVE_LARGE_FILE_SUPPORT)
  add_compile_definitions(_FILE_OFFSET_BITS=64)
  add_linker_flags(-Wl,--large-address-aware)
endif()

add_compiler_flags(-Wall -Wextra -Wthread_safety_analysis)

# including the libraries so they apply as needed.

# libraries
add_subdirectory(crypto)
add_subdirectory(univalue)

add_executable(mynerd main.cpp util.cpp)

# Target specific configs
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  find_package(SHLWAPI REQUIRED)
  # We cannot use the imported target here, because cmake will introduce an
  # -isystem compilation directive and cause the build to fail with MinGw.
  # This comes from a couple cmake bugs:
  #  - https://gitlab.kitware.com/cmake/cmake/issues/16291
  #  - https://gitlab.kitware.com/cmake/cmake/issues/19095
  # These issues are solved from cmake 3.14.1. Once this version is enforced,
  # the following can be used:
  # target_link_libraries(util SHLWAPI::shlwapi)
  target_link_libraries(mynerd ${SHLWAPI_LIBRARIES})
  target_include_directories(mynerd PUBLIC ${SHLWAPI_INCLUDE_DIRS})

  find_library(WS2_32_LIBRARY NAMES ws2_32)
  target_link_libraries(mynerd ${WS2_32_LIBRARY})
endif()

find_package(CURL 7.15.2 REQUIRED)

target_link_libraries(mynerd crypto univalue ${CURL_LIBRARIES})

