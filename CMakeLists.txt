# With Help from DeepSeek
cmake_minimum_required(VERSION 3.26)

project(dpi_classify_domain
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

# Find pkg-config
find_package(PkgConfig REQUIRED)

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
set(SRCS-y "src/main.c")

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
			${DPDK_INCLUDE_DIRS}
	)

	if(link_static)
		target_link_libraries(${target_name} PRIVATE ${DPDK_STATIC_LIBRARIES})
		message(STATUS "Linking ${target_name} statically with DPDK")
	else()
		target_link_libraries(${target_name} PRIVATE PkgConfig::DPDK)
		message(STATUS "Linking ${target_name} dynamically with DPDK")
	endif()
	target_link_libraries(${target_name} PRIVATE ${HYPERSCAN_TARGET})
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
# --------------------------------
