# Changelog

What changed in each release of Homelabus, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — before 1.0, a minor version may break.

## [0.2.1] — 2026-10-27

### Added

- Sign the images keylessly, with their SBOM and provenance attached

### Changed

- Audit the watchdog password hlb metrics deadman prints
- Spend CI's minutes on the tests, not on apt and cargo install
- Compare Homelabus with its neighbours, and write down its security model
- Name CI's runner image, as the other workflows do
- Let the installer download with wget when curl is absent
- Move a catalog app's images in one pull request

## [0.2.0] — 2026-10-27

The first public version. Homelabus was developed privately before this, and its
history starts over here.
