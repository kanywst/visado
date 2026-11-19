#!/usr/bin/env bash
# Seeds each fuzz target's corpus from the conformance vectors.
#
# The vectors hold well-formed tokens and chains signed by the keys the fuzz
# targets trust, so handing them to the fuzzer starts it past the signature
# checks instead of making it rediscover "three base64url parts separated by
# dots" from random bytes. It also means the corpus has one definition rather
# than a directory of opaque blobs nobody can regenerate.
#
# Usage: fuzz/seed-corpus.sh [conformance-dir]
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
vectors=${1:-$here/../conformance}

write() { # write <target> <name> < content
  local dir="$here/corpus/$1"
  mkdir -p "$dir"
  cat > "$dir/seed-$2"
}

hash() { shasum | cut -c1-8; }

# Transaction Tokens, valid and negative. The negative ones are the valuable
# seeds: well-formed enough to reach deep into verification before failing.
jq -r '[.valid[].token, .negative[].token] | .[]' "$vectors/txn-token/vectors.json" |
  while IFS= read -r token; do
    h=$(printf '%s' "$token" | hash)
    printf '%s' "$token" | write txn_token_verify "txn-$h"
    # The same token as the subject of a token request, one pair per line.
    printf '%s\n' \
      "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
      "requested_token_type=urn:ietf:params:oauth:token-type:txn_token" \
      "audience=trust-domain.example" \
      "scope=trade.stocks" \
      "subject_token=$token" \
      "subject_token_type=urn:ietf:params:oauth:token-type:self_signed" \
      'request_context={"req_ip":"69.151.72.123"}' \
      'request_details={"action":"BUY"}' | write txn_token_request "req-$h"
    # And as the credentials a caller presents.
    printf '%s\nWPT %s\n%s' "$token" "$token" "$token" | write credentials_authenticate "wimse-$h"
    printf '\nBearer %s\n' "$token" | write credentials_authenticate "bearer-$h"
  done

# AAT presentations: the chain, the PoP, the tool and the arguments.
jq -r '.vectors[] | [(.presentation.aat_chain | join(",")), .presentation.aat_pop,
        (.tool // ""), (.args_json // "")] | @json' \
  "$vectors/aat/aat-jws-vectors.json" |
  while IFS= read -r row; do
    h=$(printf '%s' "$row" | hash)
    printf '%s' "$row" | jq -j '.[0], "\n", .[1], "\n", .[2], "\n", .[3]' |
      write aat_verify "aat-$h"
    printf '%s' "$row" | jq -j '.[0]' | write aat_decode "chain-$h"
  done

# AuthZEN responses: there are no vectors, so a few shapes the parser must
# take or refuse.
printf '{"decision":true}' | write authzen_response "permit"
printf '{"decision":false,"context":{"reason_admin":{"en":"no"}}}' | write authzen_response "deny"
printf '{"decision":"true"}' | write authzen_response "string"

for dir in "$here"/corpus/*/; do
  printf '%s: %s seeds\n' "$(basename "$dir")" "$(find "$dir" -name 'seed-*' | wc -l | tr -d ' ')"
done
