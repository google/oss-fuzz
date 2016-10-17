# Life of a bug

## New bugs

New crashes with security implications are automatically filed into our [bug
tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list). These issues are not
viewable by the public, but library developers can be automatically CC'ed on
these issues, granting access.

These bugs contain a link to a ClusterFuzz report, which contains crash details
along with a testcase that can be downloaded. This can only be accessed by
people who are CC'ed on the bug (requires a Google account).

## Fixing

Once the bug is fixed, our fuzzing infrastructure (ClusterFuzz) automatically
verifies the fix, adding a comment and closing the bug.

## Disclosure deadlines.

TBD. Bugs will be automatically derestricted after a certain time once they're
made available to the library developers, or when they're fixed.
