Fixtures for `.github/workflows/release-candidate.yml` and
`scripts/release-check.sh`.

`stub-broker/` is served over plain HTTP on 127.0.0.1 during the image smoke
test. The bridge reads a localhost broker's key from its support document
instead of DNSSEC (its dev exception in `pds-bridge/src/main.rs`), so the
image can start with no network. The key is the public key of RFC 8032
test vector 1, which signs nothing real.
