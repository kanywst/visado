//! Replacement Transaction Tokens (§13.15).

use serde_json::{Map, Value};

use crate::claims::{Scope, TxnTokenClaims};
use crate::error::TxnTokenError;
use crate::token::VerifiedTxnToken;

/// What a replacement may change.
#[derive(Debug, Clone, Default)]
pub struct Replacement {
    /// A narrower scope. `None` keeps the current one.
    pub scope: Option<Scope>,
    /// Members to add to `tctx`. Existing members cannot be changed.
    pub tctx_additions: Map<String, Value>,
    /// A new `rctx`. `None` keeps the current one.
    pub rctx: Option<Map<String, Value>>,
    /// The workload requesting the replacement, which becomes `req_wl`.
    pub req_wl: Option<String>,
}

/// Builds the claims of a replacement token.
///
/// `txn`, `sub` and `aud` are carried over unchanged. `scope` may only narrow,
/// `tctx` may only grow, and an expired token cannot be replaced. The new token
/// is valid from `now` for `lifetime` seconds, but never past `max_exp` when one
/// is given, which is how a caller limits lifetime extension.
///
/// The draft requires the call chain to be preserved but leaves the method
/// open. This function keeps `tctx` and records nothing else; callers that
/// track the chain add it through `tctx_additions`.
///
/// # Errors
///
/// [`TxnTokenError::Expired`], [`TxnTokenError::ScopeEscalation`],
/// [`TxnTokenError::TctxModified`], or whatever [`TxnTokenClaims::check`]
/// returns for the result.
pub fn replace(
    previous: &VerifiedTxnToken,
    replacement: Replacement,
    now: u64,
    lifetime: u64,
    max_exp: Option<u64>,
) -> Result<TxnTokenClaims, TxnTokenError> {
    let old = &previous.claims;
    if now >= old.exp {
        return Err(TxnTokenError::Expired);
    }

    let scope = match replacement.scope {
        Some(scope) if !scope.is_subset_of(&old.scope) => {
            return Err(TxnTokenError::ScopeEscalation);
        }
        Some(scope) => scope,
        None => old.scope.clone(),
    };

    let mut tctx = old.tctx.clone().unwrap_or_default();
    for (member, value) in replacement.tctx_additions {
        match tctx.get(&member) {
            Some(existing) if *existing != value => {
                return Err(TxnTokenError::TctxModified { member });
            }
            _ => {
                tctx.insert(member, value);
            }
        }
    }

    let mut exp = now.saturating_add(lifetime);
    if let Some(max_exp) = max_exp {
        exp = exp.min(max_exp);
    }

    let claims = TxnTokenClaims {
        iss: old.iss.clone(),
        iat: now,
        aud: old.aud.clone(),
        exp,
        txn: old.txn.clone(),
        sub: old.sub.clone(),
        scope,
        req_wl: replacement.req_wl.unwrap_or_else(|| old.req_wl.clone()),
        tctx: if tctx.is_empty() { None } else { Some(tctx) },
        rctx: replacement.rctx.or_else(|| old.rctx.clone()),
    };
    claims.check()?;
    Ok(claims)
}

/// Checks that `next` is a valid replacement of `previous`, for a recipient
/// that sees both tokens.
///
/// # Errors
///
/// [`TxnTokenError::ImmutableClaimChanged`] if `txn`, `sub` or `aud` differ,
/// [`TxnTokenError::ScopeEscalation`] if the scope widened, or
/// [`TxnTokenError::TctxModified`] if an existing `tctx` member changed or
/// disappeared.
pub fn check_replacement(
    previous: &TxnTokenClaims,
    next: &TxnTokenClaims,
) -> Result<(), TxnTokenError> {
    for (claim, old, new) in [
        ("txn", &previous.txn, &next.txn),
        ("sub", &previous.sub, &next.sub),
        ("aud", &previous.aud, &next.aud),
    ] {
        if old != new {
            return Err(TxnTokenError::ImmutableClaimChanged { claim });
        }
    }
    if !next.scope.is_subset_of(&previous.scope) {
        return Err(TxnTokenError::ScopeEscalation);
    }
    if let Some(old_tctx) = &previous.tctx {
        let new_tctx = next.tctx.as_ref();
        for (member, value) in old_tctx {
            if new_tctx.and_then(|t| t.get(member)) != Some(value) {
                return Err(TxnTokenError::TctxModified {
                    member: member.clone(),
                });
            }
        }
    }
    Ok(())
}
