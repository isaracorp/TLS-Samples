/** @file main.c
 *
 * @brief Sample TLS server application.
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
#include "itls_config.h"
#include "itls_net.h"
#include "itls_publickey.h"
#include "itls_retval.h"
#include "itls_tls.h"
#include "itls_x509.h"
#include "itls_x509certificate.h"
#include "itls_x509crl.h"

// Declare memset_s() if the platform supports it.
#if !defined(__linux__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#if defined(_WIN32) || defined(_WIN64)
// For SecureZeroMemory().
#include <Windows.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CONCURRENT_CONNECTIONS      1000
#define FLAG_TLS_HANDSHAKE_COMPLETED    0x01
#define FLAG_READ_COMPLETED             0x02
#define FLAG_SEND_CLOSE_NOTIFY          0x04

#define DEFAULT_HOST_ADDRESS            "localhost"
#define DEFAULT_PORT_NUMBER             "4433"
#define DEFAULT_CERT_CHAIN_FILE         "ecdsa_server_cert_chain.pem"
#define DEFAULT_PRIVATE_KEY_FILE        "ecdsa_server_private_key.pem"
#define DEFAULT_SERVER_RESPONSE         "Hello there, I am server. Quantum revolution is here!\n"


// A server_connection object encapsulating
// one server-client connection.
typedef struct {
    // Server socket connected to a client socket.
    itls_NetIOSocket *server_socket;

    // TLS connection context.
    itls_TLSContext *context;

    // Number of bytes already written to the
    // client connected to the server socket.
    size_t server_msg_written_size;

    // Bit-wise flags marking the various states
    // of the TLS connection.
    uint8_t flags;
} server_connection;


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

        fprintf(stdout, "      %s\n", name);
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
    fprintf(stdout, "server \n");

    // Host address at which the server process is listening.
    fprintf(stdout, "  [--host_address <host_address>] \n");

    // Port number of the server process.
    fprintf(stdout, "  [--port <port_number>] \n");

    // File containing the response message to send to the client.
    fprintf(stdout, "  [--response_file <filename>] \n");

    // "cert_chain_file" contains server cert and all intermediate CA certs, in PEM format.
    // The server cert must come first in the file followed by intermediate CA certs in cert-chain order.
    //
    // "private_key_file" contains the private key corresponding to the server cert.
    //
    // These two options must be provided together.
    fprintf(stdout, "  [--cert_chain_file <filename> --private_key_file <filename>] \n");

    // "client_auth_root_certs_file" contains root CA certs used to verify client certificates.
    // By specifying this option, client authentication is enabled. By default, client authentication
    // is disabled on the server side.
    //
    // "crl_file" contains certificate revocation list used to check during client authentication
    // if any client certificate is revoked. This is optional. This option should only be specified
    // when client authentication is enabled.
    fprintf(stdout, "  [--client_auth_root_certs_file <filename> [--crl_file <filename>]] \n");

    // A list of cipher suites to be used by the server.
    fprintf(stdout, "  [--cipher_suites <cipher_suite_1>[,<cipher_suite_2>,...]]\n");

    // Print usage.
    fprintf(stdout, "  [--help]\n");

    fprintf(stdout, "\n");
    fprintf(stdout, "  Defaults are: \n");
    fprintf(stdout, "      --host %s\n", DEFAULT_HOST_ADDRESS);
    fprintf(stdout, "      --port %s\n", DEFAULT_PORT_NUMBER);
    fprintf(stdout, "      --cert_chain_file %s\n", DEFAULT_CERT_CHAIN_FILE);
    fprintf(stdout, "      --private_key_file %s\n", DEFAULT_PRIVATE_KEY_FILE);
    fprintf(stdout, "\n");

    print_available_ciphersuites_list();
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval preamble(const char *cmd, const char *host, const char *port, const char *response_file,
    const char *cert_chain_file, const char *private_key_file, const char *root_certs_file, const char *crl_file,
    itls_Ciphersuite *ciphersuites_list, size_t list_size)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    host address: %s:%s\n", host, port);

    if (response_file != NULL) {
        fprintf(stdout, "    file containing the response message to send to client: %s\n", response_file);
    }

    fprintf(stdout, "    server certificate chain file: %s\n", cert_chain_file);
    fprintf(stdout, "    server private key file: %s\n", private_key_file);

    if (root_certs_file != NULL) {
        fprintf(stdout, "    root CA certificates file: %s\n", root_certs_file);
    }

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

static itls_retval parse_commandline(int argc, char *argv[], const char **host, const char **port, const char **response_file,
    const char **cert_chain_file, const char **private_key_file, const char **root_certs_file, const char **crl_file,
    itls_Ciphersuite **ciphersuites, size_t *ciphersuites_size)
{
    int i = 1;
    itls_retval ret = ITLS_OK;

    while (i < argc) {
        /* Options without arguments. */
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

            *host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0) {
            /* [--port <port_number>] */

            *port = argv[++i];
        } else if (strcmp(argv[i], "--response_file") == 0) {
            /* [--response_file <filename>] */

            *response_file = argv[++i];
        } else if (strcmp(argv[i], "--cert_chain_file") == 0) {
            /* [--cert_chain_file <filename>] */

            *cert_chain_file = argv[++i];
        } else if (strcmp(argv[i], "--private_key_file") == 0) {
            /* [--private_key_file <filename>] */

            *private_key_file = argv[++i];
        } else if (strcmp(argv[i], "--client_auth_root_certs_file") == 0) {
            /* [--client_auth_root_certs_file <filename>] */

            *root_certs_file = argv[++i];
        } else if (strcmp(argv[i], "--crl_file") == 0) {
            /* [--crl_file <filename>] */

            *crl_file = argv[++i];
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
// Create a server connection object.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval create_server_connection(itls_TLSConfig *config, itls_NetIOSocket *server_socket, server_connection **connection)
{
    server_connection *conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return ITLS_ENOMEM;
    }

    conn->server_socket = server_socket;

    // Create a TLS context.
    itls_retval ret = itls_TLSContextCreate(config, &(conn->context));
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextCreate(): %s\n", itls_StrError(ret));

        goto fail;
    }

    // Set the server socket for the TLS context.
    ret = itls_TLSContextSetIOSocket(conn->context, server_socket);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextSetIOSocket(): %s\n", itls_StrError(ret));

        goto fail;
    }

    *connection = conn;

    return ITLS_OK;

fail:
    itls_TLSContextDestroy(&(conn->context));
    free(conn);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Destroy a server connection object.
// ---------------------------------------------------------------------------------------------------------------------------------

static void destroy_server_connection(server_connection **connection, size_t *num_connections, int client_index)
{
    server_connection *p = *connection;

    itls_NetIOSocketShutdown(p->server_socket);
    itls_TLSContextDestroy(&(p->context));
    itls_NetIOSocketDestroy(&(p->server_socket));
    free(p);
    *connection = NULL;
    (*num_connections)--;

    fprintf(stdout, "Connection with client \"%d\" terminated.\n\n", client_index);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Set server authentication info (server certificate chain and server private key) for server authentication.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval set_server_authentication_info(itls_TLSConfig *config, itls_X509CertChain **server_cert_chain,
    itls_PrivateKey **server_priv_key, const char *cert_chain_file, const char *private_key_file)
{
    uint8_t *priv_key_buffer = NULL;
    size_t priv_key_buffer_size = 0;
    uint8_t *cert_chain_buffer = NULL;
    size_t cert_chain_buffer_size = 0;
    uint32_t num_cert_loaded = 0;
    uint32_t num_cert_failed = 0;

    // Load the server cert chain from file.
    itls_retval ret = load_data(cert_chain_file, &cert_chain_buffer, &cert_chain_buffer_size);
    if (ret != ITLS_OK) {
        goto end;
    }

    // Load the server private key from file.
    ret = load_data(private_key_file, &priv_key_buffer, &priv_key_buffer_size);
    if (ret != ITLS_OK) {
        goto end;
    }

    fprintf(stdout, "Create a certificate chain object and import the server certificate chain into it.\n");

    ret = itls_X509CertChainCreate(server_cert_chain);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainCreate(): %s\n", itls_StrError(ret));
        goto end;
    }

    ret = itls_X509CertChainImportCertificates(*server_cert_chain, cert_chain_buffer, cert_chain_buffer_size);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainImportCertificates(): %s\n", itls_StrError(ret));
        goto end;
    }

    ret = itls_X509CertChainGetCertificateCount(*server_cert_chain, &num_cert_loaded, &num_cert_failed);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainGetCertificateCount(): %s\n", itls_StrError(ret));
        goto end;
    }

    fprintf(stdout, "%d certificate(s) imported.\n", num_cert_loaded);

    if (num_cert_failed != 0) {
        fprintf(stderr, "Failed to import server certificate chain.\n");
        ret = ITLS_EX509ERROR;
        goto end;
    }

    fprintf(stdout, "Create a private key object and import the server private key into it.\n");

    // Encrypted private keys are not yet supported.
    ret = itls_PrivateKeyImport(priv_key_buffer, priv_key_buffer_size, NULL, 0, server_priv_key);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_PrivateKeyImport(): %s\n", itls_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Set the server certificate chain and private key for the TLS connection.\n");

    ret = itls_TLSConfigSetAuthenticationInfo(config, *server_cert_chain, *server_priv_key, NULL);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSConfigSetAuthenticationInfo(): %s\n", itls_StrError(ret));
        goto end;
    }

end:
    if (priv_key_buffer != NULL) {
        secure_memzero(priv_key_buffer, priv_key_buffer_size);
    }

    free(priv_key_buffer);
    free(cert_chain_buffer);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Set root CA certificates and CRLs for client authentication.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval set_root_ca_certs_crl(itls_TLSConfig *config, itls_X509CertChain **root_certs, itls_X509CRLChain **crls,
    const char *root_certs_file, const char *crl_file)
{
    uint8_t *root_certs_buffer = NULL;
    size_t root_certs_buffer_size = 0;
    uint8_t *crls_buffer = NULL;
    size_t crl_buffer_size = 0;

    // Load the root ca certs from file.
    itls_retval ret = load_data(root_certs_file, &root_certs_buffer, &root_certs_buffer_size);
    if (ret != ITLS_OK) {
        goto end;
    }

    if (crl_file != NULL) {
        // Load the CRL from file.
        ret = load_data(crl_file, &crls_buffer, &crl_buffer_size);
        if (ret != ITLS_OK) {
            goto end;
        }
    }

    fprintf(stdout, "Create a certificate object and import root CA certificates into it.\n");

    ret = itls_X509CertChainCreate(root_certs);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainCreate(): %s\n", itls_StrError(ret));
        goto end;
    }

    ret = itls_X509CertChainImportCertificates(*root_certs, root_certs_buffer, root_certs_buffer_size);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_X509CertChainImportCertificates(): %s\n", itls_StrError(ret));
        goto end;
    }

    if (crls_buffer != NULL) {
        fprintf(stdout, "Create a CRL object and import CRLs into it.\n");

        ret = itls_X509CRLChainCreate(crls);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_X509CRLChainCreate(): %s\n", itls_StrError(ret));
            goto end;
        }

        ret = itls_X509CRLChainImportCRLs(*crls, crls_buffer, crl_buffer_size);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_X509CRLChainImportCRLs(): %s\n", itls_StrError(ret));
            goto end;
        }
    }

    fprintf(stdout, "Set the root CA certificates and CRLs for client authentication.\n");

    ret = itls_TLSConfigSetAuthorityChains(config, *root_certs, *crls);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSConfigSetAuthorityChains(): %s\n", itls_StrError(ret));
        goto end;
    }

end:
    free(root_certs_buffer);
    free(crls_buffer);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Perform TLS handshake.
// ---------------------------------------------------------------------------------------------------------------------------------

static itls_retval perform_handshake(itls_TLSContext *context, int client_index)
{
    itls_Ciphersuite ciphersuite;
    const char *ciphersuite_name = NULL;
    const char *version = NULL;
    uint32_t verify_bits = 0;

    itls_retval ret = itls_TLSContextPerformHandshake(context);
    if (ret == ITLS_EREADAGAIN || ret == ITLS_EWRITEAGAIN) {
        // Connection is blocked on this socket.

        return ret;
    } else if (ret == ITLS_ECONNCLOSED || ret == ITLS_ECONNRESET) {
        // The current connection has been terminated by the client.

        fprintf(stdout, "Client \"%d\" has closed the connection.\n", client_index);

        return ret;
    } else if (ret == ITLS_EX509CERTVERIFYFAILED) {
        // This case occurs only if client authentication is enabled.

        ret = itls_TLSContextGetX509VerifyResult(context, &verify_bits);
        if (ret == ITLS_EX509CERTVERIFYFAILED) {
            fprintf(stderr, "Failed to verify the client certificate, with 0x%08x flag.\n", verify_bits);
        } else {
            fprintf(stderr, "Failed on itls_TLSContextGetX509VerifyResult(): %s\n", itls_StrError(ret));
        }

        return ret;
    } else if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextPerformHandshake(): %s\n", itls_StrError(ret));
        return ret;
    }

    fprintf(stdout, "TLS handshake completed with client \"%d\":\n", client_index);

    // Print some information about the connection.
    ret = itls_TLSContextGetCiphersuite(context, &ciphersuite);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSContextGetCiphersuite(): %s\n", itls_StrError(ret));
        return ret;
    }

    ciphersuite_name = NULL;
    ret = itls_CiphersuiteGetName(ciphersuite, &ciphersuite_name);
    if (ret == ITLS_OK) {
        fprintf(stdout, "    Negotiated cipher suite is %s.\n", ciphersuite_name);
    } else {
        fprintf(stderr, "Failed on itls_CiphersuiteGetName(): %s\n", itls_StrError(ret));
        return ret;
    }

    ret = itls_TLSContextGetVersionString(context, &version);
    if (ret == ITLS_OK) {
        fprintf(stdout, "    Negotiated version is %s.\n", version);
    } else {
        fprintf(stderr, "Failed on itls_TLSContextGetVersionString(): %s\n", itls_StrError(ret));
        return ret;
    }

    return ITLS_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Server entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    itls_TLSConfig *config = NULL;
    itls_X509CertChain *server_cert_chain = NULL;
    itls_PrivateKey *server_priv_key = NULL;
    itls_NetListenSocket *listen_socket = NULL;
    itls_NetIOSocket *server_socket = NULL;
    itls_X509CertChain *root_certs = NULL;
    itls_X509CRLChain *crls = NULL;

    // Only one listening socket is needed for polling.
    itls_NetListenSocket *listen_socket_pool[1] = { NULL };
    itls_NetListenSocket *listen_socket_available[1] = { NULL };

    // The following are used for supporting a maximum of
    // MAX_CONCURRENT_CONNECTIONS simultaneous client connections.
    itls_NetIOSocket *read_poll_sockets[MAX_CONCURRENT_CONNECTIONS] = { NULL };
    itls_NetIOSocket *write_poll_sockets[MAX_CONCURRENT_CONNECTIONS] = { NULL };
    itls_NetIOSocket *server_socket_read_available[MAX_CONCURRENT_CONNECTIONS] = { NULL };
    itls_NetIOSocket *server_socket_write_available[MAX_CONCURRENT_CONNECTIONS] = { NULL };
    server_connection *connection_pool[MAX_CONCURRENT_CONNECTIONS] = { NULL };
    size_t num_connections = 0;

    const char *host = DEFAULT_HOST_ADDRESS;
    const char *port = DEFAULT_PORT_NUMBER;
    const char *response_file = NULL;
    const char *cert_chain_file = DEFAULT_CERT_CHAIN_FILE;
    const char *private_key_file = DEFAULT_PRIVATE_KEY_FILE;
    const char *root_certs_file = NULL;
    const char *crl_file = NULL;

    uint8_t default_server_response[] = DEFAULT_SERVER_RESPONSE;
    uint8_t *server_response_msg = NULL;
    size_t server_response_msg_size = 0;
    size_t bytes_written = 0;

    uint8_t client_request_msg[1024] = { 0 };
    size_t client_request_msg_remaining_size = 0;
    size_t client_request_msg_read = 0;

    itls_Ciphersuite *ciphersuite_list = NULL;
    size_t ciphersuite_list_size = 0;

    itls_retval ret = ITLS_OK;

    // Parse commandline arguments.
    ret = parse_commandline(argc, argv, &host, &port, &response_file, &cert_chain_file, &private_key_file, &root_certs_file,
        &crl_file, &ciphersuite_list, &ciphersuite_list_size);
    if (ret != ITLS_OK) {
        goto cleanup;
    }

    // If client auth is not enabled (i.e., there is no root certs file), then it is incorrect to set the CRL file.
    if ((crl_file != NULL && root_certs_file == NULL)) {
        fprintf(stderr, "In order to set --crl_file, you must also set --client_auth_root_certs_file.\n");
        usage();
        ret = ITLS_EBADVALUE;
        goto cleanup;
    }

    // Print server options.
    ret = preamble(argv[0], host, port, response_file, cert_chain_file, private_key_file, root_certs_file, crl_file,
        ciphersuite_list, ciphersuite_list_size);
    if (ret != ITLS_OK) {
        goto cleanup;
    }

    fprintf(stdout, "Create a TLS configuration object.\n");

    ret = itls_TLSConfigCreate(ITLS_ENDPOINT_TYPE_SERVER, ITLS_TRANSPORT_TYPE_TLS, ITLS_PRESET_PROFILE_HYBRID_QS_SUITE_B, &config);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_TLSConfigCreate(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    if (ciphersuite_list != NULL) {
        fprintf(stdout, "Set the user specified cipher suites for the TLS connection.\n");

        ret = itls_TLSConfigSetCiphersuites(config, ciphersuite_list, ciphersuite_list_size);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_TLSConfigSetCiphersuites(): %s\n", itls_StrError(ret));
            goto cleanup;
        }
    }

    // Set the server cert chain and server private key.
    ret = set_server_authentication_info(config, &server_cert_chain, &server_priv_key, cert_chain_file, private_key_file);
    if (ret != ITLS_OK) {
        goto cleanup;
    }

    // If client auth is enabled, set the root CA certs and CRL.
    if (root_certs_file != NULL) {
        ret = itls_TLSConfigSetVerificationMode(config, ITLS_VERIFY_REQUIRED);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_TLSConfigSetVerificationMode(): %s\n", itls_StrError(ret));
            goto cleanup;
        }

        ret = set_root_ca_certs_crl(config, &root_certs, &crls, root_certs_file, crl_file);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on set_root_ca_certs_crl(): %s\n", itls_StrError(ret));
            goto cleanup;
        }
    }

    // Load server response message.
    if (response_file == NULL) {
        server_response_msg = default_server_response;
        server_response_msg_size = strlen((const char *) default_server_response);
    } else {
        ret = load_data(response_file, &server_response_msg, &server_response_msg_size);
        if (ret != ITLS_OK) {
            goto cleanup;
        }
    }

    fprintf(stdout, "Create a listening socket for the server.\n");

    ret = itls_NetListenSocketBindCreate(host, port, ITLS_NET_PROTOCOL_TCP, MAX_CONCURRENT_CONNECTIONS, &listen_socket);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_NetListenSocketBindCreate(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    ret = itls_NetListenSocketSetBlocking(listen_socket, false);
    if (ret != ITLS_OK) {
        fprintf(stderr, "Failed on itls_NetListenSocketSetBlocking(): %s\n", itls_StrError(ret));
        goto cleanup;
    }

    listen_socket_pool[0] = listen_socket;

    fprintf(stdout, "Listening for client connections...\n");

    // This server process does not terminate on its own.
    // To terminate it, you can send a signal to it, such
    // as SIGINT, and all clients still connected to it will
    // receive notification that the connection is closed.
    // You can also create signal handlers to perform extra
    // tasks in the event of receiving a signal.
    do {
        if (listen_socket_pool[0] == NULL && num_connections < MAX_CONCURRENT_CONNECTIONS) {
            // Re-enable polling of the listening socket.
            // (Polling might be disabled due to "num_connections"
            // reached MAX_CONCURRENT_CONNECTIONS.)

            listen_socket_pool[0] = listen_socket;

            break;
        }

        // The poll operation where all listening and I/O sockets are waited on.
        ret = itls_NetSocketPoll(listen_socket_pool, 1, read_poll_sockets, MAX_CONCURRENT_CONNECTIONS, write_poll_sockets,
            MAX_CONCURRENT_CONNECTIONS, -1, listen_socket_available, server_socket_read_available, server_socket_write_available);
        if (ret != ITLS_OK) {
            fprintf(stderr, "Failed on itls_NetSocketPoll(): %s\n", itls_StrError(ret));
            goto cleanup;
        }

        // Check if there are any client connection requests.
        if (listen_socket_available[0] != NULL) {
            // Loop through the connection request queue and accept
            // each incoming connection in turn.

            while (true) {
                if (num_connections >= MAX_CONCURRENT_CONNECTIONS) {
                    // Max number of concurrent connections reached.
                    // Wait for existing connections to terminate
                    // before accepting new ones.

                    // Stop polling the listening socket so that the
                    // server can focus on processing existing connections.
                    // Once more connection spots become available, the server
                    // will re-enable polling of the listening socket.
                    listen_socket_pool[0] = NULL;

                    break;
                }

                // Create a server socket by accepting an incoming connection.
                ret = itls_NetIOSocketAcceptCreate(listen_socket, &server_socket);
                if (ret == ITLS_EREADAGAIN) {
                    // No more incoming connections.

                    break;
                } else if (ret != ITLS_OK) {
                    fprintf(stderr, "Failed on itls_NetIOSocketAcceptCreate(): %s\n", itls_StrError(ret));
                    goto cleanup;
                }

                ret = itls_NetIOSocketSetBlocking(server_socket, false);
                if (ret != ITLS_OK) {
                    fprintf(stderr, "Failed on itls_NetIOSocketSetBlocking(): %s\n", itls_StrError(ret));
                    goto cleanup;
                }

                int i = 0;
                // Put the connection into the first available spot in the pool.
                for (i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
                    if (connection_pool[i] == NULL) {
                        break;
                    }
                }

                if (i == MAX_CONCURRENT_CONNECTIONS) {
                    // This indicates that there is no room in the
                    // connection_pool to hold the new connection, but
                    // this should have been prevented at the beginning
                    // of this loop with 'num_connections'.
                    // Thus, something else is wrong.

                    fprintf(stderr, "Failed adding server socket to the pool.\n");
                    ret = ITLS_EINTERNAL;
                    goto cleanup;
                }

                // Put the connection and the server socket in the same location within
                // the connection pool and the socket list.

                read_poll_sockets[i] = server_socket;
                server_socket = NULL;

                ret = create_server_connection(config, read_poll_sockets[i], &connection_pool[i]);
                if (ret != ITLS_OK) {
                    goto cleanup;
                }

                // "i" is also used as an identifier for client. This helps to distinguish
                // clients in the case of multiple concurrent client connections.
                fprintf(stdout, "Created a TLS connection object encapsulating the "
                                "server socket and a TLS context (client \"%d\").\n", i);

                num_connections++;
            }
        }

        // The client-server message transmission logic is based on a single data exchange,
        // where the client first sends a request message to the server, and then the server
        // responds to the client with a server message, and then the connection terminates.

        // Check if any socket is ready for data processing.
        for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
            if (connection_pool[i] == NULL) {
                continue;
            }

            bool read_available = (server_socket_read_available[i] != NULL);
            bool write_available = (server_socket_write_available[i] != NULL);
            // A socket is available to write unless otherwise indicated by ITLS_EWRITEAGAIN,
            // so if we weren't polling a socket for write then it's available to write.
            write_available |= (write_poll_sockets[i] == NULL);
            server_socket_read_available[i] = NULL;
            server_socket_write_available[i] = NULL;

            // If the poll indicated that the operation is available, remove the socket from the appropriate poll list.
            // It will be added back when necessary by the I/O operations below.
            if (read_available) {
                read_poll_sockets[i] = NULL;
            }
            if (write_available) {
                write_poll_sockets[i] = NULL;
            }

            // Perform TLS handshake with the client.
            if ((connection_pool[i]->flags & FLAG_TLS_HANDSHAKE_COMPLETED) == 0 && (read_available || write_available)) {
                ret = perform_handshake(connection_pool[i]->context, i);
                if (ret == ITLS_EREADAGAIN) {
                    // Connection attempted to read but was unable to. Socket needs to be polled for read.

                    read_poll_sockets[i] = connection_pool[i]->server_socket;
                    continue;
                } else if (ret == ITLS_EWRITEAGAIN) {
                    // Connection attempted to write but was unable to. Socket needs to be polled for write.

                    write_poll_sockets[i] = connection_pool[i]->server_socket;
                    continue;
                } else if (ret == ITLS_ECONNCLOSED || ret == ITLS_ECONNRESET) {
                    // Connection is closed by peer, clean up its connection and socket.

                    fprintf(stdout, "Client \"%d\" has closed the connection.\n", i);

                    destroy_server_connection(&(connection_pool[i]), &num_connections, i);
                    read_poll_sockets[i] = NULL;
                    write_poll_sockets[i] = NULL;
                    continue;
                } else if (ret != ITLS_OK) {
                    // On any other error, prepare the connection to send a close_notify alert before closing the connection.

                    connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                } else {
                    // Set "FLAG_TLS_HANDSHAKE_COMPLETED" so that the server will not call the handshake routine any more with
                    // this client.

                    connection_pool[i]->flags |= FLAG_TLS_HANDSHAKE_COMPLETED;
                }
            }

            // Read the client message.
            if ((connection_pool[i]->flags & FLAG_SEND_CLOSE_NOTIFY) == 0 &&
                (connection_pool[i]->flags & FLAG_TLS_HANDSHAKE_COMPLETED) != 0 &&
                (read_available || write_available)) {

                while (true) {
                    ret = itls_TLSContextRead(connection_pool[i]->context, client_request_msg, sizeof(client_request_msg) - 1,
                        &client_request_msg_read);
                    if (ret == ITLS_EREADAGAIN) {
                        // Connection attempted to read but was unable to. Socket needs to be polled for read.

                        read_poll_sockets[i] = connection_pool[i]->server_socket;
                        break;
                    } else if (ret == ITLS_EWRITEAGAIN) {
                        // Connection attempted to write but was unable to. Socket needs to be polled for write.

                        write_poll_sockets[i] = connection_pool[i]->server_socket;
                        break;
                    } else if (ret == ITLS_ECONNCLOSED || ret == ITLS_ECONNRESET) {
                        // Connection is closed by peer, clean up its connection and socket.

                        fprintf(stdout, "Client \"%d\" has closed the connection.\n", i);

                        destroy_server_connection(&(connection_pool[i]), &num_connections, i);
                        read_poll_sockets[i] = NULL;
                        write_poll_sockets[i] = NULL;
                        break;
                    } else if (ret == ITLS_ECLOSENOTIFY) {
                        fprintf(stdout, "Client \"%d\" has sent close_notify and will be closing the connection.\n", i);

                        // The server shall send close_notify and shut down this client connection.
                        connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                        break;
                    } else if (ret != ITLS_OK) {
                        fprintf(stderr, "Client \"%d\" failed on itls_TLSContextRead(): %s\n", i, itls_StrError(ret));

                        // On any other error, prepare the connection to send a close_notify alert before closing the connection.
                        connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                        break;
                    }

                    client_request_msg[client_request_msg_read] = '\0';

                    fprintf(stdout, "Message from client \"%d\":\n    %s\n", i, (char *) client_request_msg);

                    ret = itls_TLSContextGetBufferedByteCount(connection_pool[i]->context, &client_request_msg_remaining_size);
                    if (ret != ITLS_OK) {
                        fprintf(stderr, "Client \"%d\" failed on itls_TLSContextGetBufferedByteCount(): %s\n", i,
                            itls_StrError(ret));

                        // The server shall send close_notify and shut down this client connection.
                        connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                        break;
                    }

                    // The end of client message is marked by '\n'. Therefore,
                    // the server checks for '\n' at the end of each record.
                    // Note that this may produce false positives, and in which case
                    // the server may continue to read the rest of the client messages
                    // even though "FLAG_READ_COMPLETED" is set.
                    if (client_request_msg_remaining_size == 0 && client_request_msg[client_request_msg_read - 1] == '\n') {
                        // The entire message from this client have been read.
                        // Set "FLAG_READ_COMPLETED" so that the server can start
                        // writing message to this client.

                        connection_pool[i]->flags |= FLAG_READ_COMPLETED;
                        break;
                    }

                    if (client_request_msg_remaining_size == 0) {
                        // We have read a full TLS record. Rather than continuing to read this connection, poll it for
                        // read on the next iteration. This way if there's a lot of data coming in from this client we
                        // won't loop reading for a long time, starving out other clients.
                        read_poll_sockets[i] = connection_pool[i]->server_socket;
                        break;
                    }
                }
            }

            // Write the response to the client
            if ((connection_pool[i]->flags & FLAG_SEND_CLOSE_NOTIFY) == 0 &&
                (connection_pool[i]->flags & FLAG_READ_COMPLETED) != 0 &&
                (read_available || write_available)) {

                fprintf(stdout, "Write message to client \"%d\".\n", i);

                do {
                    ret = itls_TLSContextWrite(connection_pool[i]->context,
                        server_response_msg + connection_pool[i]->server_msg_written_size,
                        server_response_msg_size - connection_pool[i]->server_msg_written_size, &bytes_written);
                    if (ret == ITLS_EREADAGAIN) {
                        // Connection attempted to read but was unable to. Socket needs to be polled for read.

                        read_poll_sockets[i] = connection_pool[i]->server_socket;
                        break;
                    } else if (ret == ITLS_EWRITEAGAIN) {
                        // Connection attempted to write but was unable to. Socket needs to be polled for write.

                        write_poll_sockets[i] = connection_pool[i]->server_socket;
                        break;
                    } else if (ret == ITLS_ECONNCLOSED || ret == ITLS_ECONNRESET) {
                        // Connection is closed by peer, clean up its connection and socket.

                        fprintf(stdout, "Client \"%d\" has closed the connection.\n", i);
                        destroy_server_connection(&(connection_pool[i]), &num_connections, i);
                        read_poll_sockets[i] = NULL;
                        write_poll_sockets[i] = NULL;
                        break;
                    } else if (ret == ITLS_ECLOSENOTIFY) {
                        fprintf(stdout, "Client \"%d\" has sent close_notify and will be closing the connection.\n", i);

                        // The server shall send close_notify and shut down this client connection.
                        connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                        break;
                    } else if (ret != ITLS_OK) {
                        fprintf(stderr, "Client \"%d\" failed on itls_TLSContextWrite(): %s\n", i, itls_StrError(ret));

                        // On any other error, prepare the connection to send a close_notify alert before closing the connection.
                        connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                        break;
                    }

                    connection_pool[i]->server_msg_written_size += bytes_written;
                } while (connection_pool[i]->server_msg_written_size < server_response_msg_size);

                if (connection_pool[i]->server_msg_written_size == server_response_msg_size) {
                    // The server has finished writing the server message.
                    // Next, write 'close_notify' to the client.
                    // Setting "FLAG_SEND_CLOSE_NOTIFY" causes the server
                    // to send 'close_notify' in the next write operation.

                    fprintf(stdout, "Finished writing message to client \"%d\".\n", i);

                    connection_pool[i]->flags |= FLAG_SEND_CLOSE_NOTIFY;
                }
            }

            // Send a close_notify alert and close the client connection.
            if ((connection_pool[i]->flags & FLAG_SEND_CLOSE_NOTIFY) != 0 && write_available) {
                ret = itls_TLSContextCloseNotify(connection_pool[i]->context);
                if (ret == ITLS_EWRITEAGAIN) {
                    // Connection attempted to write but was unable to. Socket needs to be polled for write.

                    write_poll_sockets[i] = connection_pool[i]->server_socket;
                    continue;
                } else if (ret == ITLS_ECONNCLOSED || ret == ITLS_ECONNRESET) {
                    fprintf(stdout, "Client \"%d\" has closed the connection.\n", i);
                } else if (ret != ITLS_OK) {
                    fprintf(stderr, "Client \"%d\"  failed on itls_TLSContextPerformHandshake(): %s\n", i, itls_StrError(ret));
                }

                // Shutdown and cleanup the connection.

                destroy_server_connection(&(connection_pool[i]), &num_connections, i);
                read_poll_sockets[i] = NULL;
                write_poll_sockets[i] = NULL;
            }
        }
    } while (true);

cleanup:
    itls_NetListenSocketDestroy(&listen_socket);

    for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
        if (connection_pool[i] != NULL) {
            destroy_server_connection(&(connection_pool[i]), &num_connections, i);
        }
    }

    itls_TLSConfigDestroy(&config);
    itls_X509CertChainDestroy(&server_cert_chain);
    itls_PrivateKeyDestroy(&server_priv_key);
    itls_X509CertChainDestroy(&root_certs);
    itls_X509CRLChainDestroy(&crls);

    free(ciphersuite_list);

    if (response_file != NULL) {
        free(server_response_msg);
    }

    return (ret == ITLS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
