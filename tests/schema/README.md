# Vendored SARIF schema

`sarif-schema-2.1.0.json` is the official OASIS SARIF 2.1.0 (errata 01) JSON schema,
vendored byte-for-byte so CI validates the exporter without network access.

- Source: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
- SHA-256: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- `$schema`: `http://json-schema.org/draft-04/schema#`
- License: the SARIF specification and its schemata are published by OASIS (see
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317415).

Regenerate (only on a deliberate spec update, then rerun `tests/test_sarif_schema.py`):

```bash
curl -fsSL https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json \
  -o tests/schema/sarif-schema-2.1.0.json
sha256sum tests/schema/sarif-schema-2.1.0.json   # update this file and the README if it changes
```

Do not edit the schema; the exporter adapts to it, not the other way around.
