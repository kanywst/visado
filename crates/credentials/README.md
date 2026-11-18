# visado-credentials

Caller authentication for visado: a WIMSE Workload Identity Token with a Workload Proof Token (via [wimsey](https://github.com/kanywst/wimsey)), optionally with a user access token bound through the proof's `oth` claim, or an OAuth access token alone. WPT `jti` replay is checked in memory.

Pre-alpha. Licensed under Apache-2.0.
