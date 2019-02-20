/** @file main.c
 *
 * @brief Sample TLS client application.
 *
 * @copyright Copyright 2019 ISARA Corporation
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
#include "itls_config.h"
#include "itls_net.h"
#include "itls_retval.h"
#include "itls_tls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
// Declare memset_s() if the platform supports it.
#if !defined(__linux__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
// For SecureZeroMemory().
#include <Windows.h>
#endif

#define DEFAULT_HOST_ADDRESS        "localhost"
#define DEFAULT_PORT_NUMBER         "4433"
#define DEFAULT_CERT_CHAIN_FILE     "ecdsa_client_cert_chain.pem"
#define DEFAULT_PRIVATE_KEY_FILE    "ecdsa_client_private_key.pem"
#define DEFAULT_ROOT_CERTS_FILE     "root_certs_for_client.pem"
#define DEFAULT_CRL_FILE            "server_ca_crl.pem"
#define DEFAULT_CLIENT_REQUEST      "Hello, I am client. Are you quantum-safe?\r\n"

// ---------------------------------------------------------------------------------------------------------------------------------
// Print cipher suite names corresponding to the given cipher suite IDs.
// ---------------------------------------------------------------------------------------------------------------------------------
static itls_retval print_ciphersuite_list(itls_Ciphersuite *ciphersuites_list, size_t list_size)
{
    const char *name = NULL;

    for (size_t i = 0; i < list_size; ++i) {
        itls_retval ret = itls_CiphersuiteGetName(ciphersuites_list[i], &name);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_CiphersuiteGetName(): %s\n", itls_StrError(ret));
            return ret;
        }
        fprintf(stdout, "        %s\n", name);
        name = NULL;
    }

    return ITLS_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Print available cipher suite names.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval print_available_ciphersuites_list(void)
{
    itls_Ciphersuite *ciphersuites_list = NULL;
    size_t list_size = 0;

    itls_retval ret = itls_CiphersuiteListCreate(&ciphersuites_list, &list_size);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_CiphersuiteListCreate(): %s\n", itls_StrError(ret));
        goto end;
    }

    fprintf(stdout, "  Available cipher suites:\n");
    ret = print_ciphersuite_list(ciphersuites_list, list_size);

end:
    itls_CiphersuiteListDestroy(&ciphersuites_list);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Tell the user about the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    // The command.
    fprintf(stdout, "client \n");

    // Host address of the server process to connect to.
    fprintf(stdout, "  [--host_address <host_address>] \n");

    // Port number of the server process to connect to.
    fprintf(stdout, "  [--port <port_number>] \n");

    // Host name that matches the server certificate's subject alternative names or common name.
    // Use "none" to override the default with no host name.
    fprintf(stdout, "  [--host_name <host_name> | none] \n");

    // Request to send to the server.
    fprintf(stdout, "  [--request_file <filename>] \n");

    // "private_key_file" contains the private key corresponding to the client cert.
    //
    // "cert_chain_file" contains client cert and all intermediate CA certs, in PEM format.
    // The client cert must come first in the file followed by intermediate CA certs in cert-chain order.
    //
    // These are used for client authentication.
    // By default, these files are set internally so that the client is always prepared to do
    // client authentication. To unset the default, use "--no_client_auth".
    fprintf(stdout, "  [--private_key_file <filename> --cert_chain_file <filename> | --no_client_auth] \n");

    // This file contains root CA certs used to verify server certificates.
    fprintf(stdout, "  [--root_certs_file <filename>] \n");

    // This file contains certificate revocation list used to check during server authentication
    // if any server certificate is revoked.
    // Use "none" to override the default with no CRL.
    fprintf(stdout, "  [--crl_file <filename> | none] \n");

    // A list of cipher suites to be used by the client.
    fprintf(stdout, "  [--cipher_suites <cipher_suite_1>[,<cipher_suite_2>,...]]\n");

    // Print usage.
    fprintf(stdout, "  [--help]\n");

    fprintf(stdout, "\n");
    fprintf(stdout, "  Defaults are: \n");
    fprintf(stdout, "      --host_address %s\n", DEFAULT_HOST_ADDRESS);
    fprintf(stdout, "      --port %s\n", DEFAULT_PORT_NUMBER);
    fprintf(stdout, "      --host_name %s\n", DEFAULT_HOST_ADDRESS);
    fprintf(stdout, "      --private_key_file %s\n", DEFAULT_PRIVATE_KEY_FILE);
    fprintf(stdout, "      --cert_chain_file %s\n", DEFAULT_CERT_CHAIN_FILE);
    fprintf(stdout, "      --root_certs_file %s\n", DEFAULT_ROOT_CERTS_FILE);
    fprintf(stdout, "      --crl_file %s\n", DEFAULT_CRL_FILE);
    fprintf(stdout, "\n");

    print_available_ciphersuites_list();
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval preamble(const char *cmd, const char *host_address, const char *port, const char *host_name,
    const char *request_file, const char *key_file, const char *cert_chain_file, const char *root_certs_file, const char *crl_file,
    itls_Ciphersuite *ciphersuites_list, size_t list_size)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    host address: %s:%s\n", host_address, port);
    if (host_name != NULL) {
        fprintf(stdout, "    host name: %s\n", host_name);
    }
    if (request_file != NULL) {
        fprintf(stdout, "    file containing request to send to server: %s\n", request_file);
    } else {
        fprintf(stdout, "    request to send to server: %s\n", DEFAULT_CLIENT_REQUEST);
    }
    if (key_file != NULL && cert_chain_file != NULL) {
        fprintf(stdout, "    client private key file: %s\n", key_file);
        fprintf(stdout, "    client certificate chain file: %s\n", cert_chain_file);
    }
    fprintf(stdout, "    root CA certificates file: %s\n", root_certs_file);
    if (crl_file != NULL) {
        fprintf(stdout, "    Certificate Revocation List (CRL) file: %s\n", crl_file);
    }
    if (ciphersuites_list != NULL) {
        fprintf(stdout, "    preferred cipher suites:\n");
        itls_retval ret = print_ciphersuite_list(ciphersuites_list, list_size);
        if (ret != ITLS_OK) {
            return ret;
        }
    }
    fprintf(stdout, "\n");

    return ITLS_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Parse cipher suites commandline arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval parse_ciphersuites_list(const char *suites, itls_Ciphersuite **ciphersuites, size_t *num_ciphersuites)
{
    itls_retval ret = ITLS_OK;
    size_t suites_len = strnlen(suites, 256) + 1;
    itls_Ciphersuite *id_list = NULL;
    size_t list_size = 0;

    char *name_list = calloc(1, suites_len);
    if (name_list == NULL) {
        ret = ITLS_ENOMEM;
        goto fail;
    }

    memcpy(name_list, suites, suites_len);
    char *name_list_ptr = name_list;

    for (size_t i = 0; i < suites_len; ++i) {
        if (name_list_ptr[i] == ',') {
            name_list_ptr[i] = '\0';
            list_size++;
        }
    }
    list_size++;

    id_list = calloc(list_size, sizeof(*id_list));
    if (id_list == NULL) {
        ret = ITLS_ENOMEM;
        goto fail;
    }

    for (size_t j = 0; j < list_size; ++j) {
        ret = itls_CiphersuiteGetId(name_list_ptr, &id_list[j]);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on cipher suite <%s> in <%s> with itls_CiphersuiteGetId(): %s\n",
              name_list_ptr, suites, itls_StrError(ret));
            usage();
            ret = ITLS_EBADVALUE;
            goto fail;
        }
        name_list_ptr += strlen(name_list_ptr) + 1;
    }

    *num_ciphersuites = list_size;
    *ciphersuites = id_list;

    free(name_list);
    return ITLS_OK;

fail:
    free(name_list);
    free(id_list);

    return ret;
}


// ---------------------------------------------------------------------------------------------------------------------------------
// Parse commandline arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval parse_commandline(int argc, char *argv[], const char **host_address, const char **port, const char **host_name,
    const char **request_file, const char **key_file, const char **cert_file, const char **root_certs_file, const char **crl_file,
    itls_Ciphersuite **ciphersuites, size_t *ciphersuites_size)
{
    int i = 1;
    itls_retval ret = ITLS_OK;

    while (i < argc) {
        /* Options without arguments. */
        if (strcmp(argv[i], "--no_client_auth") == 0) {
            /* [--no_client_auth] */
            *key_file = NULL;
            *cert_file = NULL;
            i++;
            continue;
        }

        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return ITLS_EBADVALUE;
        }

        /* Options with arguments.*/
        if (i + 2 > argc) {
            fprintf(stderr, "Failed to parse command line arguments.\n");
            usage();
            return ITLS_EBADVALUE;
        }

        if (strcmp(argv[i], "--host_address") == 0) {
            /* [--host_address <host_address>] */
            *host_address = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0) {
            /* [--port <port>] */
            *port = argv[++i];
        } else if (strcmp(argv[i], "--host_name") == 0) {
            /* [--host_name <host_name> | none] */
            const char *arg = argv[++i];
            if (strcmp(arg, "none") == 0) {
                *host_name = NULL;
            } else {
                *host_name = arg;
            }
        } else if (strcmp(argv[i], "--request_file") == 0) {
            /* [--request_file <filename>] */
            *request_file = argv[++i];
        } else if (strcmp(argv[i], "--private_key_file") == 0) {
            /* [--private_key_file <filename>] */
            *key_file = argv[++i];
        } else if (strcmp(argv[i], "--cert_chain_file") == 0) {
            /* [--cert_chain_file <filename>] */
            *cert_file = argv[++i];
        } else if (strcmp(argv[i], "--root_certs_file") == 0) {
            /* [--root_certs_file <filename>] */
            *root_certs_file = argv[++i];
        } else if (strcmp(argv[i], "--crl_file") == 0) {
            /* [--crl_file <filename> | none] */
            const char *arg = argv[++i];
            if (strcmp(arg, "none") == 0) {
                *crl_file = NULL;
            } else {
                *crl_file = arg;
            }
        } else if (strcmp(argv[i], "--cipher_suites") == 0) {
            /* [--cipher_suites <cipher_suite_1>[,<cipher_suite_2>,...]] */
            const char *suites = argv[++i];
            ret = parse_ciphersuites_list(suites, ciphersuites, ciphersuites_size);
            if (ret != ITLS_OK) {
                return ret;
            }
        } else {
            fprintf(stderr, "Failed to parse the command line argument: %s\n", argv[i]);
            usage();
            return ITLS_EBADVALUE;
        }

        i++;
    }

    return ITLS_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Secure memory wipe.
// ---------------------------------------------------------------------------------------------------------------------------------

static void secure_memzero(void *b, size_t len)
{
    /* You may need to substitute your platform's version of a secure memset()
     * (one that won't be optimized out by the compiler). There isn't a secure,
     * portable memset() available before C11 which provides memset_s(). Windows
     * provides SecureZeroMemory() for this purpose.
     */
#if defined(__STDC_LIB_EXT1__) || (defined(__APPLE__) && defined(__MACH__))
    memset_s(b, len, 0, len);
#elif defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(b, len);
#else
    /* This fallback will not be optimized out, if the compiler has a conforming
     * implementation of "volatile". It also won't take advantage of any faster
     * intrinsics, so it may end up being slow.
     *
     * Implementation courtesy of this paper:
     * http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf
     */
    volatile unsigned char *ptr = b;
    while (len--) {
        *ptr++ = 0x00;
    }
#endif
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Generic POSIX file read.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        fprintf(stderr, "Did you run the sample from the directory containing the executable and example PEM files?\n");
        return ITLS_EBADVALUE;
    }

    /* Obtain file size. */
    fseek(fp , 0 , SEEK_END);
    size_t tmp_size = (size_t)ftell(fp);
    rewind(fp);

    itls_retval ret = ITLS_OK;
    uint8_t *tmp = NULL;
    if (tmp_size != 0) {

        /* calloc with a param of 0 could return a pointer or NULL depending on
         * implementation, so skip all this when the size is 0 so we
         * consistently return NULL with a size of 0. In some samples it's
         * useful to take empty files as input so users can pass NULL or 0 for
         * optional parameters.
         */
        tmp = calloc(1, tmp_size);
        if (tmp == NULL) {
            fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
            ret = ITLS_EBADVALUE;
            goto end;
        }

        size_t read_size = fread(tmp, 1, tmp_size, fp);
        if (read_size != tmp_size) {
            fprintf(stderr, "Failed on fread(): %s\n", strerror(errno));
            free(tmp);
            tmp = NULL;
            ret = ITLS_EBADVALUE;
            goto end;
        }
    }

    *data_size = tmp_size;
    *data = tmp;

    fprintf(stdout, "Successfully loaded %s (%zu bytes)\n", fname, *data_size);

end:
    fclose(fp);
    fp = NULL;

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Set client authentication info (client certificate chain and client private key) for client authentication.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval set_client_authentication_info(itls_TLSConfig *config, itls_PrivateKey **private_key, itls_X509CertChain **certs,
    const char *key_file, const char *cert_file)
{
    uint8_t *private_key_buffer = NULL;
    size_t private_key_buffer_size = 0;
    uint8_t *cert_buffer = NULL;
    size_t cert_buffer_size = 0;

    itls_retval ret = load_data(key_file, &private_key_buffer, &private_key_buffer_size);
    if (ret != ITLS_OK) {
        goto end;
    }

    ret = load_data(cert_file, &cert_buffer, &cert_buffer_size);
    if (ret != ITLS_OK) {
        goto end;
    }

    // Encrypted private keys are not supported yet.
    ret = itls_PrivateKeyImport(private_key_buffer, private_key_buffer_size, NULL, 0, private_key);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_PrivateKeyImport(): %s\n", itls_StrError(ret));
        goto end;
    }

    ret = itls_X509CertChainCreate(certs);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainCreate(): %s\n", itls_StrError(ret));
        goto end;
    }

    // Import the certificate that is associated with the private key.
    ret = itls_X509CertChainImportCertificates(*certs, cert_buffer, cert_buffer_size);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainImportCertificates(): %s\n", itls_StrError(ret));
        goto end;
    }

    ret = itls_TLSConfigSetAuthenticationInfo(config, *certs, *private_key, NULL);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSConfigSetAuthenticationInfo(): %s\n", itls_StrError(ret));
        goto end;
    }

end:
    if (private_key_buffer != NULL) {
        secure_memzero(private_key_buffer, private_key_buffer_size);
    }
    free(private_key_buffer);
    free(cert_buffer);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Set root CA certificates and CRLs for server authentication.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval set_root_ca_certs_crl(itls_TLSConfig *config, itls_X509CertChain **trusted_certs,
    itls_X509CRLChain **trusted_crls, const char *root_certs_file, const char *crl_file)
{
    uint8_t *root_certs_buffer = NULL;
    size_t root_certs_buffer_size = 0;
    uint8_t *crl_buffer = NULL;
    size_t crl_buffer_size = 0;

    itls_retval ret = load_data(root_certs_file, &root_certs_buffer, &root_certs_buffer_size);
    if (ret != ITLS_OK) {
        goto end;
    }

    ret = itls_X509CertChainCreate(trusted_certs);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainCreate(): %s\n", itls_StrError(ret));
        goto end;
    }

    // Import the certificate.
    ret = itls_X509CertChainImportCertificates(*trusted_certs, root_certs_buffer, root_certs_buffer_size);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainImportCertificates(): %s\n", itls_StrError(ret));
        goto end;
    }

    // Import the CRL.
    if (crl_file != NULL) {
        ret = itls_X509CRLChainCreate(trusted_crls);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_X509CRLChainCreate(): %s\n", itls_StrError(ret));
            goto end;
        }

        ret = load_data(crl_file, &crl_buffer, &crl_buffer_size);
        if (ret != ITLS_OK) {
            goto end;
        }

        ret = itls_X509CRLChainImportCRLs(*trusted_crls, crl_buffer, crl_buffer_size);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_X509CRLChainImportCRLs(): %s\n", itls_StrError(ret));
            goto end;
        }
    }

    ret = itls_TLSConfigSetAuthorityChains(config, *trusted_certs, *trusted_crls);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSConfigSetAuthorityChains(): %s\n", itls_StrError(ret));
        goto end;
    }

end:
    free(root_certs_buffer);
    free(crl_buffer);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Client's entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    itls_NetIOSocket *socket = NULL;
    itls_TLSContext *context = NULL;
    itls_TLSConfig *config = NULL;
    itls_PrivateKey *private_key = NULL;
    itls_X509CertChain *client_certs = NULL;
    itls_X509CertChain *trusted_certs = NULL;
    itls_X509CRLChain *trusted_crls = NULL;

    const char *host_address = DEFAULT_HOST_ADDRESS;
    const char *port = DEFAULT_PORT_NUMBER;
    const char *host_name = DEFAULT_HOST_ADDRESS;
    const char *request_file = NULL;
    const char *key_file = DEFAULT_PRIVATE_KEY_FILE;
    const char *cert_chain_file = DEFAULT_CERT_CHAIN_FILE;
    const char *root_certs_file = DEFAULT_ROOT_CERTS_FILE;
    const char *crl_file = DEFAULT_CRL_FILE;
    uint32_t verify_bits = 0;

    uint8_t default_request[] = DEFAULT_CLIENT_REQUEST;
    uint8_t *request = NULL;
    size_t bytes_written = 0;
    size_t request_size = 0;

    uint8_t response[1024] = { 0 };
    size_t bytes_read = 0;
    size_t size = 0;

    itls_Ciphersuite *ciphersuite_list = NULL;
    size_t ciphersuite_list_size = 0;
    itls_Ciphersuite ciphersuite;
    const char *ciphersuite_name = NULL;
    const char *version = NULL;

    // Parse commandline arguments.
    itls_retval ret = parse_commandline(argc, argv, &host_address, &port, &host_name, &request_file, &key_file, &cert_chain_file,
                          &root_certs_file, &crl_file, &ciphersuite_list, &ciphersuite_list_size);
    if (ret != ITLS_OK) {
        goto cleanup;
    }

    /**
     * Load client's request.
     * For the purposes of this sample we restrict requests to text-based
     * messages that end with a new-line ('\n').
     */
    if (request_file == NULL) {
        request = default_request;
        request_size = strlen((const char *) default_request);
    } else {
        ret = load_data(request_file, &request, &request_size);
        if (ret != ITLS_OK) {
            goto cleanup;
        }
    }

    if (request[request_size - 1] != '\n') {
        fprintf(stderr, "A request is required to end with a new line character.\n");
        usage();
        ret = ITLS_EBADVALUE;
        goto cleanup;
    }

    /**
     * Private key and certificate are needed on the client-side if server
     * requires client authentication.
     */
    if ((key_file == NULL && cert_chain_file != NULL) || (key_file != NULL && cert_chain_file == NULL)) {
        fprintf(stderr, "Both of client's private key and certificate need to be present for client authentication.\n");
        usage();
        ret = ITLS_EBADVALUE;
        goto cleanup;
    }

    // On successful parameter parsing, print the used values.
    ret = preamble(argv[0], host_address, port, host_name, request_file, key_file, cert_chain_file, root_certs_file, crl_file,
            ciphersuite_list, ciphersuite_list_size);
    if (ret != ITLS_OK) {
        goto cleanup;
    }

    /**
     * 1. Setup.
     */
    ret = itls_TLSConfigCreate(ITLS_ENDPOINT_TYPE_CLIENT, ITLS_TRANSPORT_TYPE_TLS, ITLS_PRESET_PROFILE_HYBRID_QS_SUITE_B, &config);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSConfigCreate(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    if (ciphersuite_list != NULL) {
        ret = itls_TLSConfigSetCiphersuites(config, ciphersuite_list, ciphersuite_list_size);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_TLSConfigSetCiphersuites(): %s\n", itls_StrError(ret));
            goto cleanup;
        }
    }

    // Load and setup the client's private key and certificate.
    if (key_file != NULL) {
        ret = set_client_authentication_info(config, &private_key, &client_certs, key_file, cert_chain_file);
        if (ret != ITLS_OK) {
            goto cleanup;
        }
    }

    // Load and setup the trusted CA's certificate and CRL.
    ret = set_root_ca_certs_crl(config, &trusted_certs, &trusted_crls, root_certs_file, crl_file);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on set_root_ca_certs_crl(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    ret = itls_TLSContextCreate(config, &context);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextCreate(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    if (host_name != NULL) {
        ret = itls_TLSContextSetPeerName(context, host_name);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_TLSContextSetPeerName(): %s\n", itls_StrError(ret));
            goto cleanup;
        }
    }

    /**
     * 2. Create connection.
     */
    ret = itls_NetIOSocketConnectCreate(host_address, port, ITLS_NET_PROTOCOL_TCP, &socket);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_NetIOSocketConnectCreate(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    ret = itls_TLSContextSetIOSocket(context, socket);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextSetIOSocket(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    /**
     * 3. Perform handshake.
     */
    do {
        ret = itls_TLSContextPerformHandshake(context);
        if (ret != ITLS_EREADAGAIN && ret != ITLS_EWRITEAGAIN) {
            // Server's certificate verification has failed.
            if (ret == ITLS_EX509CERTVERIFYFAILED) {
                ret = itls_TLSContextGetX509VerifyResult(context, &verify_bits);
                if (ret == ITLS_EX509CERTVERIFYFAILED) {
                    if ((verify_bits & ITLS_X509_VERIFY_CERT_CN_MISMATCH) != 0) {
                        fprintf(stderr, "Failed to verify the host name (\"%s\") with the server certificate. "
                                "Full failure flag: 0x%08x.\n", host_name, verify_bits);
                    } else {
                        fprintf(stderr, "Failed to verify the server certificate, with 0x%08x flag.\n", verify_bits);
                    }
                } else {
                    fprintf(stderr, "Failed on itls_TLSContextGetX509VerifyResult(): %s\n", itls_StrError(ret));
                }
                goto cleanup;
            }

            if (ret != ITLS_OK) {
                fprintf(stderr, "Failed on itls_TLSContextPerformHandshake(): %s\n", itls_StrError(ret));
                goto cleanup;
            }
        }
    } while (ret != ITLS_OK);

    fprintf(stdout, "\nSuccessfully performed handshake.\n");

    // Print some information about the connection.
    ret = itls_TLSContextGetCiphersuite(context, &ciphersuite);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextGetCiphersuite(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    ret = itls_CiphersuiteGetName(ciphersuite, &ciphersuite_name);
    if (ret == ITLS_OK) {
        fprintf(stdout, "Negotiated cipher suite is %s.\n", ciphersuite_name);
    } else {
        fprintf(stderr, "Failed on itls_CiphersuiteGetName(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    ret = itls_TLSContextGetVersionString(context, &version);
    if (ret == ITLS_OK) {
        fprintf(stdout, "Negotiated version is %s.\n", version);
    } else {
        fprintf(stderr, "Failed on itls_TLSContextGetVersionString(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    /**
     * 4. Write a request to the server.
     */
    while (size != request_size) {
        do {
            ret = itls_TLSContextWrite(context, request + size, request_size - size, &bytes_written);
            if (ret != ITLS_EREADAGAIN && ret != ITLS_EWRITEAGAIN) {
                if (ret != ITLS_OK) {
                    fprintf(stderr, "Failed on itls_TLSContextWrite(): %s\n", itls_StrError(ret));
                    goto cleanup;
                }
            }
        } while (ret != ITLS_OK);

        size += bytes_written;
    }

    fprintf(stdout, "Successfully sent a request to the server.\n\n");

    /**
     * 5. Read Server's response.
     */
    do {
        do {
            ret = itls_TLSContextRead(context, response, sizeof(response) - 1, &bytes_read);
            if (ret == ITLS_EREADAGAIN || ret == ITLS_EWRITEAGAIN) {
                continue;
            }
            // Peer is done writing and is closing the connection.
            if (ret == ITLS_ECLOSENOTIFY) {
                fprintf(stdout, "Peer is closing the connection.\n");
                goto close_notify;
            }
            if (ret != ITLS_OK) {
                fprintf(stderr, "Failed on itls_TLSContextRead(): %s\n", itls_StrError(ret));
                goto cleanup;
            }
        } while (ret != ITLS_OK);

        response[bytes_read] = '\0';
        fprintf(stdout, "Server's response: %s\n", (char *) response);
    } while (ret == ITLS_OK);

    /**
     * 6. Close the connection.
     */
close_notify:
    do {
        ret = itls_TLSContextCloseNotify(context);
    } while(ret == ITLS_EWRITEAGAIN);
    if (ret == ITLS_OK) {
        fprintf(stdout, "Successfully closed the connection.\n");
    } else {
        fprintf(stderr, "Failed on itls_TLSContextCloseNotify(): %s\n", itls_StrError(ret));
    }

cleanup:
    // Context object holds a reference to socket and config objects, so it must be destroyed first.
    itls_TLSContextDestroy(&context);
    itls_NetIOSocketShutdown(socket);
    itls_NetIOSocketDestroy(&socket);
    // Config object holds a reference to the private key object, certificate chains, and CRL chains, so it must be destroyed first.
    itls_TLSConfigDestroy(&config);
    itls_PrivateKeyDestroy(&private_key);
    itls_X509CertChainDestroy(&client_certs);
    itls_X509CertChainDestroy(&trusted_certs);
    itls_X509CRLChainDestroy(&trusted_crls);

    free(ciphersuite_list);
    if (request_file != NULL) {
        free(request);
    }

    return (ret == ITLS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
