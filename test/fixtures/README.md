# Test fixtures

Generated with openssl on 2026-09-26 for the tests only. The private key
(`ec-private.pem`) signs test tokens for `ec-leaf.pem`; it protects nothing and
is not used anywhere else. `*.openssl.txt` hold openssl's own reading of the
certificates, which the tests compare against.

`ssh/` was generated with ssh-keygen: public keys of every type, an
unencrypted and a passphrase-protected (`correct horse`) private key,
a user certificate signed by a throwaway CA, and `fingerprints.txt` with
ssh-keygen's own SHA256 and MD5 output for the tests to compare against.
