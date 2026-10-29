# Mica R5 donor extraction

This GPLv2 patch is against YuKongA/payload_extract_rs at the revision in
source-lock.json. The upstream LICENSE is retained. It fixes BSDF2 decoding,
LZ4 HC destSize recompression, partial decoding and stored-fragment padding.
It preserves operation hashes and fails on mismatches.

Use an existing Rust toolchain and liblz4 1.10.0. The recorded build used
Rust/Cargo 1.97.1 on macOS ARM64 with two jobs. Acquire the exact upstream source
archive in source-lock.json and verify its SHA-256 before extracting. Apply
`patch -p1 < /ABSOLUTE/TO/native-lz4.patch` from that clean source root. Verify
Cargo.lock and src/extract/lz4diff.rs against source-lock.json after patching.

Put source, Cargo home, target output and temporary files inside an owned local
CleanOS task. Set CARGO_HOME, CARGO_TARGET_DIR and TMPDIR explicitly. For the
recorded Homebrew liblz4 installation, build with:

```sh
export RUSTFLAGS="-L native=/opt/homebrew/opt/lz4/lib -C link-arg=-Wl,-rpath,/opt/homebrew/opt/lz4/lib --remap-path-prefix=$TASK_SCRATCH=/build"
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
cargo build --release --locked --no-default-features -j 2
cargo test --release --locked --no-default-features -j 2 lz4diff::tests
"$CARGO_TARGET_DIR/release/payload-extract" extract "$SIGNED_R2_TO_R5_OTA" \
  --source-dir "$CLEAN_R2_IMAGES" --partitions system,product,system_ext \
  --output "$TASK_SCRATCH/donor-r5" --threads 2 --verify --verify-update
```

The two added regression tests passed. Only system, product and system_ext were
reconstructed for this donor. Regenerate their verity trees using the signed
manifest parameters, then require the complete raw image hashes below. The local
validation receipt retains those parameters and the regeneration procedure.
No FEC fields are present in this donor. Other donors, PUFFDIFF and ZUCCHINI
operations are not qualified by this result.

| Image | Bytes | SHA-256 |
| --- | ---: | --- |
| system | 1081479168 | 9cfaeb99137407f7a995e91cdac3e0ce27c6ef2891297445e6dbbc2e88d363d3 |
| system_ext | 182886400 | 8001bfe664ab35d2b49056ff9906729cb80c70720f73f240bca085efe3f41a4d |
| product | 1970008064 | d1b40955110d9f6a92cf9f597d3b6ef370a2476487c2fc47b2e0d3bea9b48297 |

These are clean donor images, not tablet firmware. Use build_native_userspace.py
schema 2 with lineage mica-r5-16693588 to compose the reviewed tablet graft and
native production integration. The schema checks all three raw hashes and the
immutable V10 graft source. Repair and tablet-posture JAR guards stay exact.
The Product release guard binds the final reviewed output, including its frozen
recipe timestamp; a changed transform requires a fresh content/metadata review.
Neither the laptop OTA nor these clean images should be flashed to the tablet.
