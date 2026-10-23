# Experimental source-built LuaJIT lane. Include after fc_core is defined.
# This deliberately does not change the default DLL or claim historical ABI parity.
option(FC_ENABLE_LUAJIT_CANDIDATE "Build the optional source-owned LuaJIT research host" OFF)

if(NOT FC_ENABLE_LUAJIT_CANDIDATE)
  return()
endif()

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "FC_ENABLE_LUAJIT_CANDIDATE requires an MSVC Win32 build")
endif()
if(NOT TARGET fc_core)
  message(FATAL_ERROR "Include LuaJitCandidate.cmake after defining fc_core")
endif()

get_filename_component(_fc_lj_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(_fc_lj_vendor "${_fc_lj_root}/third_party/luajit-candidate")
set(_fc_lj_manifest "${_fc_lj_vendor}/SOURCE_MANIFEST.json")
set(FC_LUAJIT_VENDOR_DIR "${_fc_lj_vendor}")
include("${CMAKE_CURRENT_LIST_DIR}/VerifyLuaJitCandidate.cmake")
set(_fc_lj_verify "${CMAKE_CURRENT_LIST_DIR}/VerifyLuaJitCandidate.cmake")
file(READ "${_fc_lj_manifest}" _fc_lj_json)
string(JSON _fc_lj_commit GET "${_fc_lj_json}" commit)
if(NOT _fc_lj_commit STREQUAL "1c279127050e86e99970100e9c42e0f09cd54ab7")
  message(FATAL_ERROR "Unexpected LuaJIT candidate source commit in manifest")
endif()
string(JSON _fc_lj_count LENGTH "${_fc_lj_json}" files)
math(EXPR _fc_lj_last "${_fc_lj_count} - 1")
set(_fc_lj_inputs "${_fc_lj_manifest}")
foreach(_fc_lj_i RANGE 0 ${_fc_lj_last})
  string(JSON _fc_lj_path GET "${_fc_lj_json}" files ${_fc_lj_i} path)
  string(JSON _fc_lj_hash GET "${_fc_lj_json}" files ${_fc_lj_i} sha256)
  if(_fc_lj_path MATCHES "(^/|^\\.\\.|/\\.\\./|\\\\)")
    message(FATAL_ERROR "Invalid vendored LuaJIT path: ${_fc_lj_path}")
  endif()
  set(_fc_lj_file "${_fc_lj_vendor}/${_fc_lj_path}")
  if(NOT EXISTS "${_fc_lj_file}")
    message(FATAL_ERROR "Missing vendored LuaJIT file: ${_fc_lj_path}")
  endif()
  file(SHA256 "${_fc_lj_file}" _fc_lj_actual)
  if(NOT _fc_lj_actual STREQUAL _fc_lj_hash)
    message(FATAL_ERROR "Vendored LuaJIT hash mismatch: ${_fc_lj_path}")
  endif()
  list(APPEND _fc_lj_inputs "${_fc_lj_file}")
endforeach()

if(NOT CMAKE_GENERATOR_INSTANCE)
  message(FATAL_ERROR "LuaJIT candidate expects a Visual Studio generator instance")
endif()
set(_fc_lj_vcvars "${CMAKE_GENERATOR_INSTANCE}/VC/Auxiliary/Build/vcvarsall.bat")
if(NOT EXISTS "${_fc_lj_vcvars}")
  message(FATAL_ERROR "Cannot find MSVC x86 environment: ${_fc_lj_vcvars}")
endif()

set(_fc_lj_copy "${CMAKE_CURRENT_BINARY_DIR}/luajit-candidate-copy")
set(_fc_lj_prepare "${CMAKE_CURRENT_LIST_DIR}/PrepareLuaJitCandidateCopy.cmake")
set(_fc_lj_dll "${_fc_lj_copy}/src/lua51.dll")
set(_fc_lj_lib "${_fc_lj_copy}/src/lua51.lib")
set(_fc_lj_exe "${_fc_lj_copy}/src/luajit.exe")
set(_fc_lj_build_script "${CMAKE_CURRENT_BINARY_DIR}/build-luajit-candidate.cmd")
file(GENERATE OUTPUT "${_fc_lj_build_script}" CONTENT
"@echo off\r\ncall \"${_fc_lj_vcvars}\" x86\r\nif errorlevel 1 exit /b 1\r\ncd /d \"${_fc_lj_copy}/src\"\r\nif errorlevel 1 exit /b 1\r\ncall msvcbuild.bat\r\nif not exist lua51.dll exit /b 1\r\nif not exist lua51.lib exit /b 1\r\nif not exist luajit.exe exit /b 1\r\n")

add_custom_command(
  OUTPUT "${_fc_lj_dll}" "${_fc_lj_lib}"
  BYPRODUCTS "${_fc_lj_exe}"
  COMMAND "${CMAKE_COMMAND}" "-DFC_LUAJIT_VENDOR_DIR=${_fc_lj_vendor}" -P "${_fc_lj_verify}"
  COMMAND "${CMAKE_COMMAND}" "-DFC_LUAJIT_VENDOR_DIR=${_fc_lj_vendor}"
          "-DFC_LUAJIT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}"
          "-DFC_LUAJIT_COPY_DIR=${_fc_lj_copy}" -P "${_fc_lj_prepare}"
  COMMAND cmd.exe /d /c "${_fc_lj_build_script}"
  DEPENDS ${_fc_lj_inputs} "${_fc_lj_build_script}" "${_fc_lj_verify}" "${_fc_lj_prepare}"
  VERBATIM
  COMMENT "Building pinned LuaJIT candidate from copied source (Win32/x86)"
)
add_custom_target(fc_luajit_candidate_build DEPENDS "${_fc_lj_dll}" "${_fc_lj_lib}")
add_library(fc_luajit_candidate_runtime SHARED IMPORTED GLOBAL)
set_target_properties(fc_luajit_candidate_runtime PROPERTIES
  IMPORTED_LOCATION "${_fc_lj_dll}"
  IMPORTED_IMPLIB "${_fc_lj_lib}"
  INTERFACE_INCLUDE_DIRECTORIES "${_fc_lj_vendor}/src"
)
add_dependencies(fc_luajit_candidate_runtime fc_luajit_candidate_build)

add_library(fc_lua_host STATIC "${_fc_lj_root}/src/lua_host.cpp" "${_fc_lj_root}/src/lua_events.cpp"
  "${_fc_lj_root}/src/lua_bit_writer_candidate.cpp")
target_include_directories(fc_lua_host PUBLIC "${_fc_lj_root}/include")
target_link_libraries(fc_lua_host PUBLIC fc_core fc_bit_writer fc_voice_message fc_luajit_candidate_runtime)
add_dependencies(fc_lua_host fc_luajit_candidate_build)
target_compile_options(fc_lua_host PRIVATE /W4 /permissive- /EHsc /Zi /fp:strict /arch:SSE2)

# The new factory is opt-in. The default DLL has no LuaJIT import dependency.
target_link_libraries(fc_experimental PRIVATE fc_lua_host)
target_compile_definitions(fc_experimental PRIVATE FC_ENABLE_LUAJIT_CANDIDATE=1)
add_dependencies(fc_experimental fc_luajit_candidate_build)
add_custom_command(TARGET fc_experimental POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_fc_lj_dll}" "$<TARGET_FILE_DIR:fc_experimental>"
  VERBATIM)

if(BUILD_TESTING)
  add_executable(fc_lua_host_tests "${_fc_lj_root}/tests/lua_host_tests.cpp")
  target_link_libraries(fc_lua_host_tests PRIVATE fc_lua_host)
  add_dependencies(fc_lua_host_tests fc_luajit_candidate_build)
  add_custom_command(TARGET fc_lua_host_tests POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_fc_lj_dll}" "$<TARGET_FILE_DIR:fc_lua_host_tests>"
    VERBATIM)
  add_test(NAME experimental.lua_host COMMAND fc_lua_host_tests)
  add_executable(fc_lua_events_tests "${_fc_lj_root}/tests/lua_events_tests.cpp")
  target_link_libraries(fc_lua_events_tests PRIVATE fc_lua_host)
  add_dependencies(fc_lua_events_tests fc_luajit_candidate_build)
  add_custom_command(TARGET fc_lua_events_tests POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_fc_lj_dll}" "$<TARGET_FILE_DIR:fc_lua_events_tests>"
  )
  add_test(NAME experimental.lua_events COMMAND fc_lua_events_tests)
  add_executable(fc_lua_bit_writer_candidate_tests "${_fc_lj_root}/tests/lua_bit_writer_candidate_tests.cpp")
  target_link_libraries(fc_lua_bit_writer_candidate_tests PRIVATE fc_lua_host)
  add_dependencies(fc_lua_bit_writer_candidate_tests fc_luajit_candidate_build)
  add_custom_command(TARGET fc_lua_bit_writer_candidate_tests POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_fc_lj_dll}" "$<TARGET_FILE_DIR:fc_lua_bit_writer_candidate_tests>"
    VERBATIM)
  add_test(NAME experimental.lua_bit_writer COMMAND fc_lua_bit_writer_candidate_tests)
endif()
