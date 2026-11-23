# Security policy

visado is pre-alpha and implements unfinished Internet-Drafts. Do not use it to protect production traffic.

What visado does and does not protect against is in the [assurance case](docs/assurance-case.md).

## Supported versions

Only the latest release gets security fixes. Before 1.0 a fix ships in a new patch or minor release, never as a backport, and the [changelog](CHANGELOG.md) says what changed and how to upgrade.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |
| `main` | Fixed as soon as the fix is merged |

## Reporting a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/kanywst/visado/security/advisories/new). Do not open a public issue or pull request.

Include the affected crate and version or commit, the impact, and steps to reproduce. If a pinned draft revision is involved, name it.

A flaw in a draft itself, rather than in visado's implementation of it, is still welcome here. It is fixed in visado where possible and reported to the IETF or OpenID working group with the reporter's agreement.

## What happens next

The maintainers listed in [MAINTAINERS.md](MAINTAINERS.md) handle reports.

| Step | Target |
| --- | --- |
| Acknowledge the report | 7 days |
| Assess it and tell the reporter whether it is accepted | 14 days |
| Release a fix for an accepted report | 90 days |

1. The report is acknowledged in the advisory thread.
2. It is reproduced and assessed. A report that is not accepted is closed with the reason.
3. For an accepted report, the fix is developed in a private fork of the advisory, with a regression test, and the reporter is asked to check it.
4. The fix is released, and the advisory is published with a CVE requested through GitHub. Disclosure is coordinated with the reporter, and the date can move if both sides agree.
5. The reporter is credited in the advisory and the changelog unless they prefer not to be.

If a vulnerability is already public or exploited, the fix and the advisory go out as soon as the fix is ready.
