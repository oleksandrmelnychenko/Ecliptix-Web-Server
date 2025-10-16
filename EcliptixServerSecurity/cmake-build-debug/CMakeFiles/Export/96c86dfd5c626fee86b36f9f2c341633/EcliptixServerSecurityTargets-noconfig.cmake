#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "EcliptixServer::ecliptix_server_security" for configuration ""
set_property(TARGET EcliptixServer::ecliptix_server_security APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(EcliptixServer::ecliptix_server_security PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libecliptix_server_security.1.0.0.dylib"
  IMPORTED_SONAME_NOCONFIG "@rpath/libecliptix_server_security.1.dylib"
  )

list(APPEND _cmake_import_check_targets EcliptixServer::ecliptix_server_security )
list(APPEND _cmake_import_check_files_for_EcliptixServer::ecliptix_server_security "${_IMPORT_PREFIX}/lib/libecliptix_server_security.1.0.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
