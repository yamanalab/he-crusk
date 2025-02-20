foreach(target_suffix IN ITEMS "test" "poly_func")
  set(target "benchmark_he_crusk_${target_suffix}")
  add_executable(${target}
    ${PROJECT_SOURCE_DIR}/benchmark/he_crusk/${target_suffix}.cpp)
  target_include_directories(${target} BEFORE PRIVATE ${PROJECT_SOURCE_DIR}/include)
  target_compile_features(${target} PUBLIC cxx_std_20)
  target_compile_options(${target} BEFORE PUBLIC -Wall -fopenmp -march=native)
  target_compile_options("${target}" BEFORE PUBLIC
    $<$<CONFIG:Debug>:-O0 -g3 -pg>
    $<$<CONFIG:Release>:-march=native -O3>
    $<$<CONFIG:RelWithDebInfo>:-march=native -g3 -pg -O2>)
  target_compile_definitions("${target}" PUBLIC
    $<$<CONFIG:Debug>:DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>)
  target_link_options(${target} PUBLIC -Wall -fopenmp -march=native)
  target_link_libraries(${target} PUBLIC SEAL::seal)
  set_target_properties(${target} PROPERTIES OUTPUT_NAME ${target_suffix})
  
  target_link_libraries(${target} PUBLIC obj_he_tool)
endforeach()

