cmake_minimum_required(VERSION 3.13)

project(RRHO VERSION 1.0.0 LANGUAGES CXX)

find_package(Threads REQUIRED)
find_package(SEAL 4.1.1 REQUIRED)

# Build type ###################################################################
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
    "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
    FORCE)
endif()
################################################################################


function(configure_for_compilation target)
  target_include_directories(${target} BEFORE PRIVATE ${PROJECT_SOURCE_DIR}/include)
  target_include_directories(${target} BEFORE PRIVATE ${PROJECT_SOURCE_DIR}/neural_network_module/include)
  target_compile_features(${target} PUBLIC cxx_std_20)
  # target_compile_options(${target} BEFORE PUBLIC -Wall -Wextra -fopenmp -march=native)
  target_compile_options(${target} BEFORE PUBLIC -Wall -fopenmp -march=native)
  target_compile_options("${target}" BEFORE PUBLIC
    $<$<CONFIG:Debug>:-O0 -g3 -pg>
    $<$<CONFIG:Release>:-march=native -O3>
    $<$<CONFIG:RelWithDebInfo>:-march=native -g3 -pg -O2>)
  target_compile_definitions("${target}" PUBLIC
    $<$<CONFIG:Debug>:DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>)
endfunction()

function(configure_for_link target linked_libraries)
  target_link_options(${target} PUBLIC -Wall -fopenmp -march=native)
  target_link_libraries(${target} PUBLIC SEAL::seal)
  foreach(linked_library IN LISTS linked_libraries)
    message(${linked_library})
    target_link_libraries(${target} PUBLIC ${linked_library})
  endforeach()
endfunction()

function(configure_for_library target)
  message("build target (obj): ${target}")
  configure_for_compilation("${target}")
endfunction()

function(configure_for_binary target linked_libraries)
  message("build target (bin): ${target}")
  message("linked_libraries: ${linked_libraries}")
  configure_for_compilation("${target}")
  configure_for_link("${target}" "${linked_libraries}")
endfunction()

add_library(obj_he_tool OBJECT
  ${PROJECT_SOURCE_DIR}/src/process_monitor.cpp)
configure_for_binary(obj_he_tool "")

add_subdirectory(benchmark)

