# With Help from DeepSeek
cmake_minimum_required(VERSION 3.26)

project(mini_dpi
	LANGUAGES C
	DESCRIPTION "Classify IPv4 packets based on FQDN sub-string search from the payload"
)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build Options
option(BUILD_SHARED "Build shared version" ON)
option(BUILD_STATIC "Build static version" ON)
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -g3 -ggdb -pg")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(OUTPUT_DIR ${CMAKE_BINARY_DIR}/build)
file(MAKE_DIRECTORY ${OUTPUT_DIR})

# # Auto-Version file
# if(EXISTS ${CMAKE_SOURCE_DIR}/.git)
# 	execute_process(
# 		COMMAND git describe --tags --always --dirty
# 		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
# 		OUTPUT_VARIABLE GIT_HASH
# 		OUTPUT_STRIP_TRAILING_WHITESPACE
# 		ERROR_QUIET
# 	)
# endif()
# file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)
# if(EXISTS ${CMAKE_SOURCE_DIR}/include/version.h.in)
# 	configure_file(
# 		${CMAKE_SOURCE_DIR}/include/version.h.in
# 		${CMAKE_BINARY_DIR}/generated/version.h
# 		@ONLY
# 	)
# endif()

# Find pkg-config
find_package(PkgConfig REQUIRED)

# --------------------------------
# HyperScan
# --------------------------------
## Help from https://cliutils.gitlab.io/modern-cmake/chapters/projects/submodule.html
option(USE_HYPERSCAN "Build with Hyperscan" ON)
option(USE_SYSTEM_HYPERSCAN "Prefer system-installed Hyperscan" ON)
include(CheckIncludeFile)
check_include_file("x86intrin.h" HAS_X86INTRIN)
check_include_file("unistd.h" HAS_UNISTD)
if(USE_HYPERSCAN AND (NOT HAS_X86INTRIN OR NOT HAS_UNISTD))
	message(WARNING "Missing intrinsics headers (x86intrin.h/unistd.h). Disabling Hyperscan.")
	set(USE_HYPERSCAN OFF)
endif()

# Hyperscan's CMake checks can fail to find x86intrin.h even when GCC knows it.
# Inject GCC's include path explicitly for the subproject checks.
if(USE_HYPERSCAN)
	execute_process(
		COMMAND ${CMAKE_C_COMPILER} -print-file-name=include
		OUTPUT_VARIABLE GCC_INCLUDE_DIR
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	if(EXISTS "${GCC_INCLUDE_DIR}/x86intrin.h")
		message(STATUS "Using GCC include dir for Hyperscan: ${GCC_INCLUDE_DIR}")
		set(CMAKE_REQUIRED_INCLUDES "${GCC_INCLUDE_DIR}")
		add_compile_options("-isystem" "${GCC_INCLUDE_DIR}")
	endif()
endif()
find_package(Git QUIET)

# if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
# 	option(GIT_SUBMODULE "Check submodules during build" ON)

# 	if(GIT_SUBMODULE)
# 		message(STATUS "Checking HyperScan submodule...")

# 		if(NOT EXISTS "${CMAKE_SOURCE_DIR}/hyperscan/CMakeLists.txt")
# 			message(STATUS "Initializing Hyperscan submodule...")
# 			execute_process(
# 				COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
# 				WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
# 				RESULT_VARIABLE GIT_SUBMOD_RESULT
# 			)

# 			if(NOT GIT_SUBMOD_RESULT EQUAL "0")
# 				message(WARNING "git submodule update failed. HyperScan may not be available.")
# 			endif()
# 		endif()
# 	endif()
# endif()

if(USE_HYPERSCAN AND USE_SYSTEM_HYPERSCAN)
	pkg_check_modules(HYPERSCAN QUIET libhs)
	if(HYPERSCAN_FOUND)
		message(STATUS "Using system Hyperscan via pkg-config")
	endif()
endif()

set(HYPERSCAN_SUBMODULE_USED OFF)
if(USE_HYPERSCAN AND NOT HYPERSCAN_FOUND)
	if(NOT EXISTS "${PROJECT_SOURCE_DIR}/hyperscan/CMakeLists.txt")
		message(FATAL_ERROR "Hyperscan submodule is missing. Please init submodules or disable USE_HYPERSCAN.")
	endif()

	add_subdirectory(hyperscan)
	if(TARGET hs)
		set(HYPERSCAN_TARGET hs)
	elseif(TARGET hs_shared)
		set(HYPERSCAN_TARGET hs_shared)
	elseif(TARGET hs_static)
		set(HYPERSCAN_TARGET hs_static)
	endif()
	set(HYPERSCAN_SUBMODULE_USED ON)
endif()

# --------------------------------
# DPDK
# --------------------------------
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

if(NOT DPDK_FOUND)
	message(FATAL_ERROR "no installation of DPDK found")
endif()

# if(NOT RTE_TARGET)
# 	set(RTE_TARGET "x86_64-native-linuxapp-gcc")
# endif()

# SET(APP "mini_dpi")
set(SRCS-y
	"src/mini_dpi.c"
	"src/thread_rx.c"
	"src/thread_classifier.c"
	"src/pkt_helpers.c"
)

# Function to create executable with specific linking
function(add_dpdk_executable link_static)
	if(link_static)
		set(target_suffix "static")
	else()
		set(target_suffix "shared")
	endif()

	set(target_name "${PROJECT_NAME}-${target_suffix}")
	message(STATUS "Creating target: ${target_name}")

	add_executable(${target_name} ${SRCS-y})

	# Include
	target_include_directories(${target_name}
		PRIVATE
		${CMAKE_SOURCE_DIR}/include
		# ${CMAKE_BINARY_DIR}/generated
		${DPDK_INCLUDE_DIRS}
	)

	if(link_static)
		target_link_libraries(${target_name} PRIVATE ${DPDK_STATIC_LIBRARIES})
		message(STATUS "Linking ${target_name} statically with DPDK")
	else()
		target_link_libraries(${target_name} PRIVATE PkgConfig::DPDK)
		message(STATUS "Linking ${target_name} dynamically with DPDK")
	endif()

	if(USE_HYPERSCAN)
		if(HYPERSCAN_FOUND)
			target_include_directories(${target_name} PRIVATE ${HYPERSCAN_INCLUDE_DIRS})
			target_link_libraries(${target_name} PRIVATE ${HYPERSCAN_LIBRARIES})
			target_compile_definitions(${target_name} PRIVATE USE_HYPERSCAN)
		elseif(HYPERSCAN_TARGET)
			target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR}/hyperscan/include)
			target_link_libraries(${target_name} PRIVATE ${HYPERSCAN_TARGET})
			target_compile_definitions(${target_name} PRIVATE USE_HYPERSCAN)
		else()
			message(WARNING "Hyperscan not found; falling back to memmem()")
		endif()
	endif()
	target_compile_definitions(${target_name} PRIVATE ALLOW_EXPERIMENTAL_API)

	# Set output directory
	set_target_properties(${target_name} PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
	)

	# Create symbolic link (make shared default if building both)
	if(NOT ${link_static} OR (${link_static} AND NOT BUILD_SHARED))
		add_custom_command(TARGET ${target_name} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E remove -f ${PROJECT_NAME}
			COMMAND ${CMAKE_COMMAND} -E create_symlink
				${target_name}
				${PROJECT_NAME}
			WORKING_DIRECTORY ${OUTPUT_DIR}
			COMMENT "Creating symbolic link ${PROJECT_NAME} -> ${target_name}"
		)
	endif()
endfunction()

if(BUILD_SHARED)
	add_dpdk_executable(FALSE)
	add_custom_target(shared DEPENDS "${PROJECT_NAME}-shared")
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY DEFAULT_TARGET "${PROJECT_NAME}-shared")
endif()

if(BUILD_STATIC)
	add_dpdk_executable(TRUE)
	add_custom_target(static DEPENDS "${PROJECT_NAME}-static")
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY DEFAULT_TARGET "${PROJECT_NAME}-static")
endif()

# enable_testing()
# include(CTest)
# add_executable(unit_tests test/unit_tests.c)
# target_link_libraries(tests ${DPDK_LIBRARIES})
# add_test(NAME unit_test COMMAND ./test/unit_tests -l 0-2 --vdev 'net_pcap0,rx_pcap=test/in.pcap')
