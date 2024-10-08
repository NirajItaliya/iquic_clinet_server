# iquic_learner
It's project denoted for "localhost" aioquic learner tool 

 

What is ``aioquic``?
--------------------

``aioquic`` is a library for the QUIC network protocol in Python. It features
a minimal TLS 1.3 implementation, a QUIC stack and an HTTP/3 stack.

QUIC was standardised in `RFC 9000`_ and HTTP/3 in `RFC 9114`_.
``aioquic`` is regularly tested for interoperability against other
`QUIC implementations`_.

To learn more about ``aioquic`` please `read the documentation`_.

Why should I use ``aioquic``?
-----------------------------

``aioquic`` has been designed to be embedded into Python client and server
libraries wishing to support QUIC and / or HTTP/3. The goal is to provide a
common codebase for Python libraries in the hope of avoiding duplicated effort.

Both the QUIC and the HTTP/3 APIs follow the "bring your own I/O" pattern,
leaving actual I/O operations to the API user. This approach has a number of
advantages including making the code testable and allowing integration with
different concurrency models.

Features
--------

- minimal TLS 1.3 implementation conforming with `RFC 8446`_
- QUIC stack conforming with `RFC 9000`_
   * IPv4 and IPv6 support
   * connection migration and NAT rebinding
   * logging TLS traffic secrets
   * logging QUIC events in QLOG format
- HTTP/3 stack conforming with `RFC 9114`_
   * server push support
   * WebSocket bootstrapping conforming with `RFC 9220`_
   * datagram support conforming with `RFC 9297`_

Installing
----------

The easiest way to install ``aioquic`` is to run:

.. code:: bash

    pip install aioquic

Building from source
--------------------

If there are no wheels for your system or if you wish to build ``aioquic``
from source you will need the OpenSSL development headers.

Linux
.....

On Debian/Ubuntu run:

.. code:: bash

   sudo apt install libssl-dev python3-dev

On Alpine Linux run:

.. code:: bash

   sudo apk add openssl-dev python3-dev bsd-compat-headers libffi-dev

OS X
....

On OS X run:

.. code:: bash

   brew install openssl

You will need to set some environment variables to link against OpenSSL:

.. code:: bash

   export CFLAGS=-I$(brew --prefix openssl)/include
   export LDFLAGS=-L$(brew --prefix openssl)/lib

Windows
.......

On Windows the easiest way to install OpenSSL is to use `Chocolatey`_.

.. code:: bash

   choco install openssl

You will need to set some environment variables to link against OpenSSL:

.. code:: bash

  $Env:INCLUDE = "C:\Progra~1\OpenSSL\include"
  $Env:LIB = "C:\Progra~1\OpenSSL\lib"

Running the examples
--------------------
Run server in Linux
.. code:: bash
    python3 examples/http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem -l keylog

Run clinet in Linux
.. code:: bash
    python3 examples/http3_client.py --ca-certs tests/pycacert.pem https://localhost:4433/

