# certs/

This directory contains a CA certificate (`pebble.minica.pem`) and a private key
(`pebble.minica.key.pem`) that are used to issue a end-entity certificate for the
Pebble HTTPS server.

To re-create all of the Pebble certificates run:

    minica -ca-cert pebble.minica.pem \
           -ca-key pebble.minica.key.pem \
           -domains localhost,pebble \
           -ip-addresses 127.0.0.1

From the `testdata/certs/` directory after [installing
MiniCA](https://github.com/jsha/minica#installation)