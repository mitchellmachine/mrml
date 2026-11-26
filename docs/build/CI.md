# Build and test coverage in CI

The GitHub Actions workflows in `.github/workflows/` use the oracle in
`rust-toolchain.toml` and check the recorded compiler commit. A workflow in the
tree is configuration, not evidence that GitHub ran it or that it passed.

- **Windows, native gnullvm:** build and test all Windows-admitted components.
  The stage-zero frontend uses GNU/LLVM without requiring MSVC or the Windows
  SDK. The Windows checkout also checks that tracked shell scripts are LF.
- **Linux, x86-64 GNU:** build and test all Linux-admitted components and run a
  separate AddressSanitizer sweep. No Windows toolchain or Wine substitutes for
  native Windows tests. Expanded CUDA checks build the host CUDA feature profile
  on both hosts and PTX for SM100 and SM120; these are compile-only.
- **MRML target:** build all MRML-target packages and all UEFI-target packages.
  `mrml test --all --target native` builds the relevant native component and
  runs its declared host test harness on the runner. Components without such
  a harness emit `NO_HOST_HARNESS`; they are not called passing native tests.
  A separate QEMU/OVMF TCG step builds a disposable boot fixture, creates and
  verifies its one-use signed release and requires the exact trace through native
  kernel entry. No owner keys or production deployment are used.

`--keep-going` attempts the rest of the selected packages when one fails and
still exits nonzero for the aggregate. Tests compile the selected declared
test/example/benchmark outputs; sample timings, ignored tests, conditional
external oracles and hardware-specific features are not automatically exercised.
The matrix does not build every experimental feature combination and does not
prove hardware support, native guest userspace test coverage or release readiness.

Before claiming all gates are green, check the run for the exact commit and
inspect any unavailable or ignored cases. In particular,
`mrml assurance check` remains a blocking check while the unsafe-policy backlog
is reviewed. `mrml assurance inspect` reports the full file-level backlog and
recognized unsafe attributes separately without passing or updating the gate.
