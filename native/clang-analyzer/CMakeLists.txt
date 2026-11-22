cmake_minimum_required(VERSION 3.20)
project(fuse_clang_analyzer LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)
find_package(Threads REQUIRED)
add_definitions(${LLVM_DEFINITIONS})
add_executable(fuse-clang-analyzer src/main.cpp)
target_compile_features(fuse-clang-analyzer PRIVATE cxx_std_17)
target_include_directories(fuse-clang-analyzer SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
target_link_libraries(fuse-clang-analyzer PRIVATE clang-cpp LLVM Threads::Threads)
enable_testing()
add_test(NAME version COMMAND fuse-clang-analyzer --version)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  get_filename_component(FUSE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
  add_test(NAME semantic-corpus COMMAND ${Python3_EXECUTABLE}
    "${FUSE_ROOT}/tests/test_clang_analyzer.py" NativeSemanticTests)
  set_tests_properties(semantic-corpus PROPERTIES ENVIRONMENT
    "PYTHONPATH=${FUSE_ROOT}/src;FUSE_CLANG_TEST_EXECUTABLE=$<TARGET_FILE:fuse-clang-analyzer>")
  add_test(NAME doctor COMMAND ${Python3_EXECUTABLE}
    "${FUSE_ROOT}/tests/test_clang_analyzer.py" NativeDoctorTests)
  set_tests_properties(doctor PROPERTIES ENVIRONMENT
    "PYTHONPATH=${FUSE_ROOT}/src;FUSE_CLANG_TEST_EXECUTABLE=$<TARGET_FILE:fuse-clang-analyzer>")
endif()
