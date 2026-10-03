# Project-owned dependency metadata; tpr/curl remains the exact release archive.
cmake_minimum_required(VERSION 3.16)
project(OhecoCurlDependencies LANGUAGES C)

# OPENSSL_USE_STATIC_LIBS is a FindOpenSSL search preference, not a linkage mode.
# Exact .a paths are mandatory and independently force static BoringSSL. Leave
# that preference OFF: curl's ON branch assumes Clang means GNU libstdc++.
foreach(_input OPENSSL_INCLUDE_DIR OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY)
  if(NOT DEFINED ${_input} OR NOT EXISTS "${${_input}}")
    message(FATAL_ERROR "Explicit native BoringSSL input required: ${_input}")
  endif()
endforeach()
foreach(_archive OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY)
  if(NOT "${${_archive}}" MATCHES "[.]a$")
    message(FATAL_ERROR "BoringSSL must be a static archive: ${_archive}")
  endif()
endforeach()
set(OPENSSL_USE_STATIC_LIBS OFF CACHE BOOL "Exact archives supplied; no search preference" FORCE)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
set(OB_CXX_RUNTIME "" CACHE STRING "Explicit native C++ runtime: c++ or stdc++")
if(NOT OB_CXX_RUNTIME MATCHES "^(c[+][+]|stdc[+][+])$")
  message(FATAL_ERROR "Set OB_CXX_RUNTIME to c++ or stdc++")
endif()
set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
  INTERFACE_LINK_LIBRARIES "${OB_CXX_RUNTIME};Threads::Threads;m;${CMAKE_DL_LIBS}")

# Compile with the same libc socket headers that precede linux/tcp.h in curl.
# An isolated kernel header check would miss OHOS sockaddr_storage collisions.
include(CheckCSourceCompiles)
check_c_source_compiles("\n#include <sys/types.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n#include <linux/tcp.h>\nint main(void) { struct tcp_info info; return (int)sizeof(info); }\n"
  OHECO_CURL_LINUX_TCP_COMPATIBLE)
set(HAVE_LINUX_TCP_H "${OHECO_CURL_LINUX_TCP_COMPATIBLE}" CACHE INTERNAL
  "Native kernel TCP header compatibility with libc socket headers" FORCE)

# HTTP_ONLY also disables WebSockets in pristine curl, regardless of the
# CURL_DISABLE_WEBSOCKETS flag. Pin the SDK protocol profile explicitly here
# as well as in the reproducible command-line build.
set(HTTP_ONLY OFF CACHE BOOL "HTTP/HTTPS plus WS/WSS signaling" FORCE)
set(CURL_DISABLE_HTTP OFF CACHE BOOL "SDK HTTP registration" FORCE)
set(CURL_DISABLE_WEBSOCKETS OFF CACHE BOOL "SDK persistent signaling" FORCE)
foreach(_protocol DICT FILE FTP GOPHER IMAP IPFS LDAP LDAPS MQTT POP3 RTSP SMTP TELNET TFTP)
  set(CURL_DISABLE_${_protocol} ON CACHE BOOL "Not in the SDK protocol profile" FORCE)
endforeach()

get_filename_component(_root "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_subdirectory("${_root}/tpr/curl" curl)
