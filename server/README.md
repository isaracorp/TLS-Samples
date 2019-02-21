
# ISARA Catalyst™ TLS Testbed Server Sample

## Introduction to the TLS Server

A TLS server waits for TLS client connection requests, and for each request it
performs the TLS handshake and creates a TLS connection with the client:

1. The server continually listens for incoming TLS client connection requests.
2. When a client requests to connect, it sends a list of supported 
   cipher suites in the order of preference to the server.
3. The server chooses a cipher suite and protocol version and sends them to
   the client along with its certificate chain (for server authentication) and
   key exchange parameters. The server can also optionally ask to authenticate
   the client.
4. The client responds with its own key exchange parameters, and potentially
   its certificate for client authentication.
5. The server receives the client's key exchange parameters, and responds with
   a Finished message.
6. The peers derive shared secret keys as a result of the key exchange. These
   keys are used to encrypt communcation data.

The peers are now ready to exchange application data over the established
secure connection.

Note that the Catalyst TLS sample server supports multiple concurrent TLS client
connections, with classical or quantum-safe cipher suites. Server
authentication is mandatory, and client authentication is optional and disabled
by default on the server side.

## Getting Started

We have created a sample server application that demonstrates how to use the
Catalyst TLS API to establish TLS connections with TLS clients. Here is the
simplest way to use the sample.

Build the sample application:

```
$ mkdir build
$ cd build
$ cmake -DISARA_TLS_ROOT=/path/to/isara_tls_root/ ..
$ make
```

From the `build/server` directory, execute the sample, `server`, with no
arguments to use the default parameters, or use `--help` to list the available
options.

This sample program uses certificates, private keys, and optionally CRLs
(Certificate Revocation List). We have included sample certificates,
private keys, and a CRL in this package to make it easy for you to get started:
* `ecdsa_server_cert_chain.pem`: A server certificate followed by the issuing
  intermediate CA certificate. This is the default server certificate chain
  for server authentication used by the sample.
* `ecdsa_server_private_key.pem`: The private key corresponding to the default
  server certificate.
* `ecdsa_server_revoked_cert_chain.pem`: A revoked server certificate followed
  by the issuing intermediate CA certificate. This is used to demonstrate
  client and server's CRL functionality. The sample `client` needs to set CRL
  `crl_from_server_ca.pem`.
* `ecdsa_server_revoked_private_key.pem`: The private key corresponding to the
  revoked server certificate.
* `root_certs_for_server.pem`: Root CA certificates used to verify client
  certificates. This is used for client authentication.
* `client_ca_crl.pem`: CRL used to check if any client certificate is revoked.
  This is used for client authentication.

You can also create your own server certificate chains, private keys, root CA
certificates, and CRLs using your favorite tool, e.g. OpenSSL, to use with this
sample program.

Use `--help` to see available options on setting various certificates, keys, and
CRLs for the sample `server`.

## Further Reading

* See `itls_tls.h` in the Catalyst TLS `include` directory.

## License

See the `LICENSE` file for details:

> Copyright (C) 2019, ISARA Corporation
> 
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
> 
> http://www.apache.org/licenses/LICENSE-2.0
> 
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.

### Trademarks

ISARA Catalyst™ is a trademark of ISARA Corporation.
