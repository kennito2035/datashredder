# Changelog

## v1.0.1 (2026-08-25)

### Bug Fixes

- **Progress bar can now reach 100% when files are skipped.** Files that fail the pre-shred checks (read-only, symbolic link) are no longer counted in the total byte estimate, so skipping them no longer leaves the bar stuck below 100%.
- **Progress updates throttled.** The progress bar was updated once per 64 KB chunk, flooding the event dispatch thread on large files. Updates are now posted only when the percentage changes or 100 ms have passed since the last post.

## v1.0.0

Initial release.
