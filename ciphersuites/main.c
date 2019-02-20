/** @file main.c
 *
 * @brief Sample application for displaying cipher suite names.
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

#include "itls_ciphersuite.h"
#include "itls_retval.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    // Unused arguments.
    (void)argc;
    (void)argv;

    itls_Ciphersuite *list = NULL;
    size_t list_size = 0;
    itls_retval ret = itls_CiphersuiteListCreate(&list, &list_size);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_CiphersuiteListCreate(): %s\n", itls_StrError(ret));
        return EXIT_FAILURE;
    }

    fprintf(stdout, "%zu cipher suites are supported:\n", list_size);
    for (size_t i = 0; i < list_size; i++) {
        const char *name = NULL;
        ret = itls_CiphersuiteGetName(list[i], &name);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_CiphersuiteGetName() for ID %08X: %s\n", list[i], itls_StrError(ret));
            break;
        }
        fprintf(stdout, "  %s\n", name);
    }

    itls_CiphersuiteListDestroy(&list);

    return (ret == ITLS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
