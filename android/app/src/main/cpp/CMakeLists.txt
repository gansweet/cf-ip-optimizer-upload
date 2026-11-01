cmake_minimum_required(VERSION 3.18)
project(cfip C)

find_package(curl REQUIRED CONFIG)
find_package(openssl REQUIRED CONFIG)

# 与桌面版共用同一份 C 内核：把 main 改名为 cfip_main，由 JNI 在后台线程里启动
set(CORE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../cf_ip_test_tls.c)
set_source_files_properties(${CORE} PROPERTIES COMPILE_DEFINITIONS "main=cfip_main")

add_library(cfip SHARED ${CORE} jni_wrap.c)
target_compile_options(cfip PRIVATE -O2 -Wall)
target_link_libraries(cfip curl::curl openssl::ssl openssl::crypto z log)
