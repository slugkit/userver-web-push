cmake_minimum_required(VERSION 3.12...3.31)
project(webpush_client CXX)

find_package(OpenSSL REQUIRED)

set(WEBPUSH_SRC
    # userver-style crypto extensions
    include/userver/crypto/ecdh.hpp
    include/userver/crypto/hkdf.hpp
    include/userver/crypto/aes_gcm.hpp

    src/crypto/helpers.hpp
    src/crypto/helpers.cpp
    src/crypto/ecdh.cpp
    src/crypto/hkdf.cpp
    src/crypto/aes_gcm.cpp

    # webpush types
    include/webpush/types/credentials.hpp
    include/webpush/types/subscription.hpp
    include/webpush/types/notification.hpp
    include/webpush/types/result.hpp

    src/webpush/types/credentials.cpp

    # webpush component
    include/webpush/components/client.hpp
    src/webpush/components/client.cpp

    # webpush handler
    include/webpush/handlers/debug_send.hpp
    src/webpush/handlers/debug_send.cpp

    # vapid
    src/webpush/vapid/token.hpp
    src/webpush/vapid/token.cpp

    # payload encryption
    src/webpush/encrypt/payload.hpp
    src/webpush/encrypt/payload.cpp
)

add_library(webpush_client OBJECT ${WEBPUSH_SRC})
target_link_libraries(webpush_client PUBLIC userver::core OpenSSL::Crypto)
target_include_directories(webpush_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(webpush_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(WEBPUSH_BUILD_TESTS)
    add_executable(webpush_unittest
        tests/ecdh_test.cpp
        tests/hkdf_test.cpp
        tests/aes_gcm_test.cpp
        tests/encrypt_test.cpp
        tests/vapid_test.cpp
        tests/notification_test.cpp
    )
    target_link_libraries(webpush_unittest PRIVATE webpush_client userver::utest OpenSSL::Crypto)
    target_include_directories(webpush_unittest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    add_google_tests(webpush_unittest)
endif()
