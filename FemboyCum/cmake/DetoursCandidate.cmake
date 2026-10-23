# Separate source baseline; it supplies no native HookBackend or game hooks.
option(FC_ENABLE_DETOURS_CANDIDATE "Build pinned Detours and an authored local-function test" OFF)
if(NOT FC_ENABLE_DETOURS_CANDIDATE)
  return()
endif()
if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "FC_ENABLE_DETOURS_CANDIDATE requires MSVC Win32")
endif()
get_filename_component(_fc_detours_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(FC_DETOURS_VENDOR_DIR "${_fc_detours_root}/third_party/detours-candidate")
set(_fc_detours_verify "${CMAKE_CURRENT_LIST_DIR}/VerifyDetoursCandidate.cmake")
include("${_fc_detours_verify}")
add_custom_target(fc_detours_candidate_verify
  COMMAND "${CMAKE_COMMAND}" "-DFC_DETOURS_VENDOR_DIR=${FC_DETOURS_VENDOR_DIR}"
    -P "${_fc_detours_verify}"
  VERBATIM COMMENT "Verifying exact pinned Detours source inventory and hashes")
set(_fc_detours_sources)
foreach(_fc_detours_unit detours modules disasm image creatwth
    disolx86 disolx64 disolia64 disolarm disolarm64)
  list(APPEND _fc_detours_sources "${FC_DETOURS_VENDOR_DIR}/src/${_fc_detours_unit}.cpp")
endforeach()
add_library(fc_detours_candidate STATIC ${_fc_detours_sources})
add_dependencies(fc_detours_candidate fc_detours_candidate_verify)
target_include_directories(fc_detours_candidate PUBLIC "${FC_DETOURS_VENDOR_DIR}/src")
# Upstream v4.0.1 uses MSVC C++14 extensions, including legacy goto scopes.
# Keep its files unmodified and isolate its dialect from the C++20 core.
set_target_properties(fc_detours_candidate PROPERTIES CXX_STANDARD 14
  CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS ON)
set_property(TARGET fc_detours_candidate PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
target_compile_definitions(fc_detours_candidate PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
target_compile_options(fc_detours_candidate PRIVATE /W4 /WX /Zi)
if(BUILD_TESTING)
  add_executable(fc_detours_candidate_tests "${_fc_detours_root}/tests/detours_candidate_tests.cpp")
  target_link_libraries(fc_detours_candidate_tests PRIVATE fc_detours_candidate)
  target_compile_features(fc_detours_candidate_tests PRIVATE cxx_std_20)
  set_property(TARGET fc_detours_candidate_tests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  target_compile_options(fc_detours_candidate_tests PRIVATE /W4 /WX /Zi)
  add_test(NAME research.detours_candidate COMMAND fc_detours_candidate_tests)
  if(TARGET fc_hook_transactions)
    add_executable(fc_detours_hook_backend_tests
      "${_fc_detours_root}/tests/detours_hook_backend_tests.cpp"
      "${_fc_detours_root}/tests/detours_hook_backend.cpp")
    target_include_directories(fc_detours_hook_backend_tests PRIVATE "${_fc_detours_root}/tests")
    target_link_libraries(fc_detours_hook_backend_tests PRIVATE fc_hook_transactions fc_detours_candidate)
    set_property(TARGET fc_detours_hook_backend_tests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    target_compile_options(fc_detours_hook_backend_tests PRIVATE /W4 /WX /permissive- /EHsc)
    add_test(NAME research.detours_hook_backend COMMAND fc_detours_hook_backend_tests)
  endif()
  if(TARGET fc_hook_publication)
    add_executable(fc_detours_hook_publication_tests
      "${_fc_detours_root}/tests/detours_hook_publication_tests.cpp"
      "${_fc_detours_root}/tests/detours_hook_backend.cpp")
    target_include_directories(fc_detours_hook_publication_tests PRIVATE "${_fc_detours_root}/tests")
    target_link_libraries(fc_detours_hook_publication_tests PRIVATE fc_hook_publication fc_detours_candidate)
    set_property(TARGET fc_detours_hook_publication_tests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    target_compile_options(fc_detours_hook_publication_tests PRIVATE /W4 /WX /permissive- /EHsc)
    add_test(NAME research.detours_hook_publication COMMAND fc_detours_hook_publication_tests)
  endif()
endif()
