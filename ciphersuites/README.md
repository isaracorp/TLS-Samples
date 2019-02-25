
:version-label!:
:revnumber!:
# ISARA Catalyst™ TLS Testbed Cipher Suites Sample

## Introduction to Cipher Suites

A TLS cipher suite is a collection of cryptographic primitives, such as key
agreement algorithm, symmetric cipher, and message digest algorithm, that are
used to establish and secure a TLS connection. The cipher suite algorithms are
negotiated by the peers while the connection is being established. Catalyst TLS
provides a set of functions to list the supported cipher suites and translate
them between cipher suite IDs and human-readable strings.

## Getting Started

We have created a small sample application that demonstrates how to use the
cipher suite functions.

Build the sample application:

```
$ mkdir build
$ cd build
$ cmake -DISARA_TLS_ROOT=/path/to/isara_tls_root/ ..
$ make
```

Execute the sample, `ciphersuites`. It has no parameters.

## Further Reading

* See `itls_ciphersuite.h` in the Catalyst TLS `include` directory.

## License

See the `LICENSE` file for details:

> Copyright © 2019, ISARA Corporation
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
