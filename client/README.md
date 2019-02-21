
# ISARA Catalyst™ TLS Testbed Client Sample

## Introduction to the TLS Client

A TLS client initiates a TLS handshake with a TLS server and subsequently the
two peers establish a TLS connection:

1. The client sends a list of its supported cipher suites in the
   order of preference to the server.
2. The server chooses the cipher suite and protocol version and sends them to
   the client along with its certificate (for server authentication) and key
   exchange parameters. The server can also optionally ask to authenticate the
   client. Usually applications authenticate the client over the secure channel
   after the connection is established.
3. The client responds with its own key exchange parameters, and potentially its
   certificate for client authentication.
4. The server receives the client's key exchange parameters, and responds with a
   Finished message.
5. The peers derive shared secret keys as a result of the key exchange. These
   keys are used to secure data on the connection.

The peers are now ready to exchange application data over the established secure
connection.

Note that the Catalyst TLS sample client supports classical or quantum-safe
cipher suites. It enforces server authentication. It also loads its
certificate chain and private key by default so that it is always prepared to 
do client authentication.

## Getting Started

We have created a sample client application that demonstrates how to use the
Catalyst TLS API to establish a TLS connection with a TLS server. Here is the
simplest way to use the sample:

Build the sample application:

```
$ mkdir build
$ cd build
$ cmake -DISARA_TLS_ROOT=/path/to/isara_tls_root/ ..
$ make
```

From the `build/client` directory, execute the sample, `client`, with no
arguments to use the default parameters, or use `--help` to list the available
options.

This sample program uses certificates, private keys, and CRLs
(Certificate Revocation List). We have included sample certificates,
private keys, and a CRL in this package to make it easy for you to get started:
* `ecdsa_client_cert_chain.pem`: A client certificate followed by the issuing
  intermediate CA certificate. This is the default client certificate chain
  for client authentication used by the sample.
* `ecdsa_client_private_key.pem`: The private key corresponding to the default
  client certificate.
* `ecdsa_client_revoked_cert_chain.pem`: A revoked client certificate followed
  by the issuing intermediate CA certificate. This is used to demonstrate
  client and server's CRL functionality. The sample `server` needs to set CRL
  `crl_from_client_ca.pem`.
* `ecdsa_client_revoked_private_key.pem`: The private key corresponding to the
  revoked client certificate.
* `root_certs_for_client.pem`: Root CA certificates used to verify server
  certificates. This is the default set of root CA certificates used for server
  authentication.
* `server_ca_crl.pem`: CRL used to check if any server certificate is revoked.
  This is the default CRL used for server authentication.

You can also create your own client certificate chains, private keys, root CA
certificates, and CRLs using your favorite tool, e.g. OpenSSL, to use with this
sample program.

Use `--help` to see available options on setting various certificates, keys,
and CRLs for the sample `client`.

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
