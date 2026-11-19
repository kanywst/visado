# asor vectors

`vectors/` holds the test vector set for [draft-asor-wimse-agent-delegation-chain-03](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/), copied unchanged.

| | |
| --- | --- |
| Source | [`src/attenu_guard/vectors/draft02/`](https://github.com/attenu-io/attenu-guard/tree/3f8249ea3cf0e5b8e759495b12b15d1f7f8a43bc/src/attenu_guard/vectors/draft02) in [attenu-io/attenu-guard](https://github.com/attenu-io/attenu-guard), tag `v0.22.0` |
| Commit | `3f8249ea3cf0e5b8e759495b12b15d1f7f8a43bc` |
| SHA-256 | Per file in [SHA256SUMS](SHA256SUMS) |
| Vectors | 36 (5 accept, 31 reject) |
| License | Apache-2.0, Copyright 2026 Attenu. See [NOTICE](../../NOTICE). |

The files say `"draft": "02"`: they are the set the -02 introduced, which the -03 keeps and extends to 36 files (its appendix "Reference Implementation and Test Vectors"). At this commit, which is also the head of `main`, the repository has no newer set. The older -01 set (20 files in `src/attenu_guard/vectors/`) is not vendored: its tokens carry no `cnf` or `client_id` and a null `aud`, so every one of them is malformed under the -03.

Each file gives a chain (`tokens`, root first), the verification time `now`, the test signer, and the verifier's accepted algorithms and audience. A valid chain has `"expect": "accept"`; a rejected one names the outcome of the draft's Table 2 in `expect_reject_reason`. The chains are signed with a test-only HS256 key, published in each file; the draft requires Ed25519 for real deployments.

To update, copy the directory at a new commit, regenerate `SHA256SUMS` with `shasum -a 256 *.json > ../SHA256SUMS` inside `vectors/`, update the commit above, and run `cargo test -p visado-chain-asor`.
