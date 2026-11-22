# TLOCK example

`policy.json` is an advisory local policy with an expiry.

`payload.txt` is the plaintext to encrypt.

`prf-output.b64` and `credential-id-hash.b64` are **synthetic stand-ins** for
a WebAuthn PRF output and a credential identifier hash. They are not
secrets and must never be used for anything real. In practice the PRF output
comes from the authenticator, and it should be passed with
`--prf-output-file` or `--prf-output-env` rather than on the command line.

```bash
open-extensions tlock create tlock/payload.txt secret.tlock --policy tlock/policy.json --mode passkey-local --recipient alice --credential-id-hash AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --prf-output-file tlock/prf-output.b64
open-extensions tlock open secret.tlock --mode passkey-local --recipient alice --prf-output-file tlock/prf-output.b64
```
