/** @file main.c
 *
 * @brief Display version information.
 *
 * @copyright Copyright (C) 2019, ISARA Corporation
 *
 * @license Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <a href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</a>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "itls_retval.h"
#include "itls_version.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    // Unused arguments.
    (void)argc;
    (void)argv;

    fprintf(stdout, "Header version: %d.%d\n", ITLS_VERSION_MAJOR, ITLS_VERSION_MINOR);
    fprintf(stdout, "                %s\n", ITLS_VERSION_STRING);

    int exit_value = EXIT_SUCCESS;
    itls_retval ret = itls_VersionCheck(ITLS_VERSION_MAJOR, ITLS_VERSION_MINOR);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_VersionCheck(): %s\n", itls_StrError(ret));
        exit_value = EXIT_FAILURE;
    } else {
        fprintf(stdout, "Header version matches library version.\n");
    }

    const char *build_target = NULL;
    ret = itls_VersionGetBuildTarget(&build_target);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_VersionGetBuildTarget(): %s\n", itls_StrError(ret));
        exit_value = EXIT_FAILURE;
    } else {
        fprintf(stdout, "Library build target: %s\n", build_target);
    }

    const char *build_hash = NULL;
    ret = itls_VersionGetBuildHash(&build_hash);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_VersionGetBuildHash(): %s\n", itls_StrError(ret));
        exit_value = EXIT_FAILURE;
    } else {
        fprintf(stdout, "Library build hash:\n    %s\n", build_hash);
    }

    return exit_value;
}
