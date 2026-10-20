cmake_minimum_required(VERSION 3.22)
project(RustTidecoinValidationOracle LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT TIDECOIN_NODE_REPO)
  message(FATAL_ERROR "Set TIDECOIN_NODE_REPO to the pinned clean node checkout")
endif()
get_filename_component(TIDECOIN_NODE_REPO "${TIDECOIN_NODE_REPO}" REALPATH)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../NODE_REVISION" expected_revision)
string(STRIP "${expected_revision}" expected_revision)
execute_process(COMMAND git -C "${TIDECOIN_NODE_REPO}" rev-parse HEAD
  OUTPUT_VARIABLE node_revision OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
if(NOT node_revision STREQUAL expected_revision)
  message(FATAL_ERROR "Node revision does not match NODE_REVISION")
endif()
execute_process(COMMAND git -C "${TIDECOIN_NODE_REPO}" status --porcelain --untracked-files=no -- src
  OUTPUT_VARIABLE dirty COMMAND_ERROR_IS_FATAL ANY)
if(dirty)
  message(FATAL_ERROR "Node source checkout must be clean")
endif()
file(SHA256 "${TIDECOIN_NODE_REPO}/src/validation.cpp" validation_sha256)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/../NODE_REVISION" "${TIDECOIN_NODE_REPO}/src/validation.cpp")
set(BUILD_GUI OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ENABLE_WALLET OFF CACHE BOOL "" FORCE)
set(ENABLE_IPC OFF CACHE BOOL "" FORCE)
set(WITH_CCACHE OFF CACHE BOOL "" FORCE)
set(WITH_USDT OFF CACHE BOOL "" FORCE)
add_subdirectory("${TIDECOIN_NODE_REPO}" node EXCLUDE_FROM_ALL)
add_executable(tidecoin-validation-oracle oracle.cpp)
target_include_directories(tidecoin-validation-oracle PRIVATE
  "${TIDECOIN_NODE_REPO}/src" "${CMAKE_CURRENT_BINARY_DIR}/node/src")
target_compile_definitions(tidecoin-validation-oracle PRIVATE
  ORACLE_NODE_REVISION="${node_revision}" ORACLE_VALIDATION_SHA256="${validation_sha256}")
target_link_libraries(tidecoin-validation-oracle PRIVATE core_interface tidecoin_node
  tidecoin_consensus tidecoin_common tidecoin_util tidecoin_quantum tidecoin_crypto
  tidecoin_clientversion univalue Boost::headers)
