# Life of a bug

Oss-fuzz uses a [separate issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) to track fuzzer-detected issues.
During the initial part of the issue life the issue has restricted visibility:

| State    | Visibility |
|----------|------------|
| New      | oss-fuzz engineers |
| Reported | oss-fuzz engineers + peopel CC'ed on the bug |
| Fixed & Verified | public |
| Lapsed (90 days since report) | public |

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

Bugs will be automatically derestricted after a certain time once they're
made available to the library developers, or when they're fixed.

Following [Project Zero disclosure policy](https://googleprojectzero.blogspot.com/2015/02/feedback-and-data-driven-updates-to.html)
oss-fuzz will adhere to following disclosure principles:
  - **90-day deadline**. After notifying library authors, we will open reported
    issues in 90 days, or sooner if the fix is released.
  - **Weekends and holidays**. If a deadline is due to expire on a weekend or
    US public holiday, the deadline will be moved to the next normal work day.
  - **Grace period**. We will have a 14-day grace period. If a 90-day deadline
    will expire but library engineers let us know before the deadline that a
    patch is scheduled for release on a specific day within 14 days following
    the deadline, the public disclosure will be delayed until the availability
    of the patch.
