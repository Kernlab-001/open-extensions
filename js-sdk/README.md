# JavaScript SDK (planned)

No JavaScript implementation is included in v0.1. The JS SDK should implement the same wire formats as the Python SDK and pass shared golden test vectors.

For `.memx`, the implementation must match the fixed Argon2id v1.3 profile, AES-256-GCM nonce/tag layout, authenticated header bytes, zlib stream handling, canonical JSON rules, resource limits, and payload schema. Do not substitute browser-native PBKDF2 or another KDF and still claim `.memx` v0.1 compatibility.

Implementation options (to be evaluated, not selected yet): Node.js native crypto plus a maintained Argon2id binding; browser builds only where the same KDF and crypto profile can be provided safely. Password input should use secure prompts or UI controls and must never be placed in CLI arguments or logs.
