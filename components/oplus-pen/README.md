# OplusPen component source

The `upstream-manifest.json` records the reviewed upstream commit and exact source
hashes. `upstream/`, `patches/googlebook.patch`, `LICENSE`, and
`tests/ProtocolSelfTest.kt` are retained. The upstream license and source bytes
are unchanged. Local toolchain and donor locks use generic ignored input paths
while retaining their verification hashes.

Build from the repository root with `build_oplus_pen.py` and an active local
CleanOS scratch task. See the root BUILDING.md. The integration files describe
package-scoped permissions and policy. Strict linkage and neverallow checks remain
required. Functional pen tests, refresh-rate behavior and sleep/wake need hardware
validation. Do not infer a working release from a successful source export.
