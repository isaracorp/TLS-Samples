# Copyright 2018-2019 ISARA Corporation
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

if (NOT "${ISARA_TLS_ROOT}" STREQUAL "")
    if (NOT "$ENV{ISARA_TLS_ROOT}" STREQUAL "")
        message (WARNING "ISARA_TLS_ROOT environment and cmake (possibly cached?) variables both set, using cmake variable.")
    endif ()
    message (STATUS "ITLS directory from cmake variable: ${ISARA_TLS_ROOT}")
elseif (NOT "$ENV{ISARA_TLS_ROOT}" STREQUAL "")
    message (STATUS "ITLS include directory from environment variable: $ENV{ISARA_TLS_ROOT}")
    set (ISARA_TLS_ROOT "$ENV{ISARA_TLS_ROOT}")
else ()
    message (WARNING "ISARA_TLS_ROOT environment or cmake variables not set, trying: ${CMAKE_CURRENT_LIST_DIR}/..")
    set (ISARA_TLS_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
endif ()

include_directories ("${ISARA_TLS_ROOT}/include")
link_directories ("${ISARA_TLS_ROOT}/lib")

find_file (ISARA_TLS_LIB
    NAMES libisara_tls.so libisara_tls.dylib libisara_tls.dll
    PATHS "${ISARA_TLS_ROOT}/lib")
if (NOT ISARA_TLS_LIB)
    message (ERROR " Unable to find the ISARA TLS library.")
endif ()

find_file (ISARA_TOOLKIT_LIB
    NAMES libiqr_toolkit.so libiqr_toolkit.dylib libiqr_toolkit.dll
    PATHS "${ISARA_TLS_ROOT}/lib")
if (NOT ISARA_TOOLKIT_LIB)
    message (ERROR " Unable to find the ISARA Toolkit library.")
endif ()
