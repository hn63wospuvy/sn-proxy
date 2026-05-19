# mTLS test harness

End-to-end test for sn-proxy's mutual-TLS features:

* **Client mTLS** — an `http`/`https` proxy presents a PKCS#12 client
  certificate to an upstream destination that demands one.
* **Server mTLS** — an `https` proxy's listener presents a PKCS#12 keystore
  certificate and requires connecting clients to present a certificate that
  validates against a PKCS#12 truststore.

## Files

| File | Purpose |
|------|---------|
| `gen_certs.py`  | Generates a throwaway PKI: CA, leaf certs and the three PKCS#12 files (`client.p12`, `server.p12`, `truststore.p12`). Password: `testpass`. |
| `mtls_server.py`| A destination HTTPS server that **requires** a client certificate. Listens on `127.0.0.1:9444`. |
| `test_mtls.py`  | Creates the proxies through the admin API and runs all checks. |

Generated `*.crt` / `*.key` / `*.p12` files are git-ignored.

## Running

```sh
# 1. generate the test PKI
python mtls_test/gen_certs.py

# 2. start the mTLS destination server (leave running)
python mtls_test/mtls_server.py

# 3. start sn-proxy on the admin port the test expects
target/debug/sn-proxy -p 127.0.0.1:8088 -d data_mtls

# 4. run the test
python mtls_test/test_mtls.py
```

`test_mtls.py` exits 0 when all checks pass.

## Note on truststore format

`p12-keystore` (sn-proxy's PKCS#12 reader) surfaces a bare certificate only
when it carries the Java "trusted certificate" attribute that
`keytool -importcert` writes. A CA carried inside a key entry's certificate
chain is read by every toolchain, so `gen_certs.py` writes the truststore that
way. In production, use a `keytool`-produced truststore or one whose entries
include the CA in a key chain.
