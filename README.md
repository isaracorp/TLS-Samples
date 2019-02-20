# ISARA Catalyst™ TLS 0.1 Testbed Samples

## Samples

Sample code for Catalyst TLS.  Each directory has a self-contained program
inside demonstrating how to use Catalyst TLS for a specific purpose:

* `client` &mdash; A client demonstrating how to use TLS to connect to a
  server, perform a TLS handshake with classical or quantum-safe cipher suites
  with optional client authentication, and exchange application data securely.
* `server` &mdash; A server demonstrating how to accept multiple incoming
  connections, perform TLS handshakes with classical or quantum-safe cipher
  suites and exchange application data securely.
* `version` &mdash; Display the library's version information.

### Building Samples

**NOTE**
Before building the samples, copy one of the CPU-specific versions of the
libraries into a `lib` directory. For example, to build the samples for Intel
64 bit CPUs, copy the contents of `lib_x86_64` into `lib`.

The samples use the `ISARA_TLS_ROOT` CMake or environment variable to determine
the location of the libraries to build against. CMake requires that environment
variables are set on the same line as the CMake command, or are exported
environment variables in order to be read properly. If `ISARA_TLS_ROOT` is a
relative path, it must be relative to the directory where you're running the
`cmake` command.

1. Install Catalyst TLS somewhere, e.g. `/path/to/isara_tls_root/`.
2. `cd` to the `samples` directory, such as `/path/to/isara_tls/samples/`.
3. Use `mkdir` to make a `build` directory; `cd` into the `build` directory.
3. Run CMake: `cmake -DISARA_TLS_ROOT=/path/to/isara_tls_root/ ..` or
   `ISARA_TLS_ROOT=/path/to/isara_tls_root cmake ..` The `..` in there refers to
   the parent of your `build` directory, so it'll pick up the `CMakeLists.txt`
   in the main `samples` directory.
4. Run make: `make`

This will build all of the samples in individual directories under the `build`
directory.

**NOTE**
Don't build the samples on macOS using `gcc` 8, they will crash before `main()`
due to a problem with `-fstack-protector-all`. Use `clang` to produce Mac
binaries.

To build individual samples:

1. Install Catalyst TLS somewhere, e.g. `/path/to/isara_tls_root/`.
2. `cd` to the specific `samples` directory, such as
   `/path/to/isara_tls/samples/client`.
3. Use `mkdir` to make a `build` directory; `cd` into the `build` directory.
3. Run CMake: `cmake -DISARA_TLS_ROOT=/path/to/isara_tls_root/ ..` or
   `ISARA_TLS_ROOT=/path/to/isara_tls_root cmake ..` The `..` in there refers to
   the parent of your `build` directory, so it'll pick up the `CMakeLists.txt`
   in the specific `samples` directory (the one in `client` in this case).
4. Run make: `make`

This will build the specific sample in the `build` directory.

### Running Samples

See individual `README.html` files in the sample subdirectories for instructions
on running specific samples.

Execute the samples with no arguments to use the default parameters, or use
`--help` to list the available options.

### Security Issues

For information about reporting security issues, please read the
[SECURITY](SECURITY.md)
document.

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
