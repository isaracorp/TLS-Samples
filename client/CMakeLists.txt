# Copyright 2019 ISARA Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CMake or same-line/exported environment variables you need to use:
#
# * ISARA_TLS_ROOT set to the ISARA TLS root directory.

cmake_minimum_required (VERSION 3.7)
cmake_policy (SET CMP0054 NEW)

project (client)

include (../find_isara_tls.cmake)
include (../compiler_options.cmake)

add_executable (client main.c)
target_link_libraries (client ${ISARA_TLS_LIB} ${ISARA_TOOLKIT_LIB})

# Copy the client private keys, certificates, and CRL to the executable directory.
set(
    PEM_FILES

    ecdsa_client_cert_chain.pem
    ecdsa_client_revoked_cert_chain.pem
    ecdsa_client_private_key.pem
    ecdsa_client_revoked_private_key.pem
    root_certs_for_client.pem
    server_ca_crl.pem
    )

foreach(pem_file ${PEM_FILES})
  add_custom_command(
     OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${pem_file}
     COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${pem_file} ${CMAKE_CURRENT_BINARY_DIR}/${pem_file}
     DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/${pem_file}
  )

  add_custom_target(copy_${pem_file} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${pem_file})
endforeach()
