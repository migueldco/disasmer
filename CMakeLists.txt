cmake_minimum_required(VERSION 3.10)

project(disasmer VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SOURCES
    src/main.cpp
	src/binary/binary.cpp
	include/binary.hpp
	include/elf_binary.hpp
	include/elf_types.hpp
	src/disassemble/x86-64.cpp
	include/disassemble.hpp
	src/analysis/demangle.cpp
	include/demangle.hpp
)

add_executable(disasmer ${SOURCES})

include_directories(include)

target_compile_options(disasmer PRIVATE -Wall -Wextra -pedantic -Werror)
