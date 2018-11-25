cmake_minimum_required(VERSION 3.2)

if($ENV{TRAVIS_BUILD_NUMBER})
    set(VERSION_BUILD $ENV{TRAVIS_BUILD_NUMBER})
else()
    set(VERSION_BUILD 1)
endif()

project (dns_proxy VERSION 0.0.${VERSION_BUILD})

set(HEADER_PATH "${PROJECT_SOURCE_DIR}/include")

set(SOURCE_PATH "${PROJECT_SOURCE_DIR}/src")

set(HEADER_FILES "${SOURCE_PATH}/settings.h"
                 "${SOURCE_PATH}/dnsproxy.h"
                 "${SOURCE_PATH}/embed/rbtree.h"
                 )

set(SOURCE_FILES "${SOURCE_PATH}/settings.c"
                 "${SOURCE_PATH}/transport_cache.c"
                 "${SOURCE_PATH}/embed/rbtree.c"
                 )

add_executable(dns_proxy ${SOURCE_PATH}/dnsproxy.c ${HEADER_FILES} ${SOURCE_FILES})

target_link_libraries (dns_proxy -lconfig)

set_target_properties(dns_proxy PROPERTIES
	COMPILE_OPTIONS "-Wpedantic;-Wall;-Wextra"
)

install (TARGETS dns_proxy RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT danil.chest@gmail.com)

include (CPack)
