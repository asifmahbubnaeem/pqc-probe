# Releasing

One version number covers the three crates, the Docker image, the binaries and the action.

## Before the tag

1. Set the version in `Cargo.toml` (`[workspace.package]` and the `pqc-probe-core` entry in
   `[workspace.dependencies]`), run `cargo check` so `Cargo.lock` follows, and commit. While the
   version is 0.x, anything under "Breaking" in the changelog needs the minor number raised
   (0.1.x to 0.2.0): `cargo publish` builds the CLI and web crates against the core version
   their dependency names, and a patch release of core cannot change its public types.
2. In `CHANGELOG.md`, replace `- unreleased` with the date for this version
   (`## [0.1.0] - 2026-11-20`). The release job refuses a version still marked unreleased.
3. `ci` is green on `main`. Optionally run the `release` workflow by hand: it builds and checks
   the static binaries without publishing anything.
4. `cargo publish --workspace --dry-run --locked` passes (needs a crates.io account; run
   `cargo login` once with a token from crates.io).

## Tag

```bash
git tag -a v0.1.0 -m "pqc-probe v0.1.0"
git push origin v0.1.0
```

The tag starts two workflows:

- `image`: publishes `ghcr.io/asifmahbubnaeem/pqc-probe` as `0.1.0`, `0.1`, `0`, `latest`.
  The action pinned to `@v0.1.0` uses the `0.1.0` image, so it works once this finishes.
- `release`: checks the tag against `Cargo.toml`, builds static x86-64 Linux binaries and
  creates the GitHub Release with notes from the changelog and a SHA-256 checksum.

## crates.io

```bash
cargo publish --workspace --locked
```

Cargo publishes `pqc-probe-core` first, then `pqc-probe` and `pqc-probe-web`. A published
version can never be replaced (only yanked), so do the dry run first.

## Once, after the first image

Set the GHCR package's visibility to public (package settings), and check that an anonymous
`docker pull ghcr.io/asifmahbubnaeem/pqc-probe:latest` works.
