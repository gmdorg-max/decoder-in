# Test fixtures

Generated with openssl on 2026-09-26 for the tests only. The private key
(`ec-private.pem`) signs test tokens for `ec-leaf.pem`; it protects nothing and
is not used anywhere else. `*.openssl.txt` hold openssl's own reading of the
certificates, which the tests compare against.
