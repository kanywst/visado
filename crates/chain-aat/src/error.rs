//! Errors, each tied to the §8 step that failed.

use std::fmt;

use visado_chain::ChainError;

/// A step of the §8 chain verification algorithm.
/// Steps compare in the draft's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Step {
    S1,
    S2a,
    S2b,
    S2c,
    S3a,
    S3b,
    S3c,
    S3d,
    S3e,
    S3f,
    S3g,
    S3h,
    S3i,
    S3j,
    S3k,
    S3l,
    S3m,
    S3n,
    S4a,
    S4b,
    S4b1,
    S4b2,
    S4b3,
    S4b4,
    S4b5,
    S4c,
    S4d,
    S4e,
    S4f,
    S4g,
    S4h,
    S4i,
    S4j,
    S4k,
    S4l,
    S4m,
    S4n,
    S4o,
    S4p1,
    S4p2,
    S4p3,
    S4p4,
    S4q,
    S5,
    S6a,
    S6b,
    S6c,
    S7a,
    S7b,
    S7c,
    S7d,
    S7e,
    S7f,
    S7g,
    S7h,
    S7i,
}

impl Step {
    /// The step label as the draft writes it, such as `"4p2"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S1 => "1",
            Self::S2a => "2a",
            Self::S2b => "2b",
            Self::S2c => "2c",
            Self::S3a => "3a",
            Self::S3b => "3b",
            Self::S3c => "3c",
            Self::S3d => "3d",
            Self::S3e => "3e",
            Self::S3f => "3f",
            Self::S3g => "3g",
            Self::S3h => "3h",
            Self::S3i => "3i",
            Self::S3j => "3j",
            Self::S3k => "3k",
            Self::S3l => "3l",
            Self::S3m => "3m",
            Self::S3n => "3n",
            Self::S4a => "4a",
            Self::S4b => "4b",
            Self::S4b1 => "4b1",
            Self::S4b2 => "4b2",
            Self::S4b3 => "4b3",
            Self::S4b4 => "4b4",
            Self::S4b5 => "4b5",
            Self::S4c => "4c",
            Self::S4d => "4d",
            Self::S4e => "4e",
            Self::S4f => "4f",
            Self::S4g => "4g",
            Self::S4h => "4h",
            Self::S4i => "4i",
            Self::S4j => "4j",
            Self::S4k => "4k",
            Self::S4l => "4l",
            Self::S4m => "4m",
            Self::S4n => "4n",
            Self::S4o => "4o",
            Self::S4p1 => "4p1",
            Self::S4p2 => "4p2",
            Self::S4p3 => "4p3",
            Self::S4p4 => "4p4",
            Self::S4q => "4q",
            Self::S5 => "5",
            Self::S6a => "6a",
            Self::S6b => "6b",
            Self::S6c => "6c",
            Self::S7a => "7a",
            Self::S7b => "7b",
            Self::S7c => "7c",
            Self::S7d => "7d",
            Self::S7e => "7e",
            Self::S7f => "7f",
            Self::S7g => "7g",
            Self::S7h => "7h",
            Self::S7i => "7i",
        }
    }

    /// The stable error code for a failure at this step.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::S1 => "aat.empty_chain",
            Self::S2a | Self::S2b => "aat.too_large",
            Self::S2c => "aat.token_repeated",
            Self::S3a | Self::S4a | Self::S7a => "aat.bad_header",
            Self::S3b | Self::S4b | Self::S7b => "aat.bad_signature",
            Self::S3c
            | Self::S3i
            | Self::S4b4
            | Self::S4d
            | Self::S4e
            | Self::S4f
            | Self::S4g
            | Self::S4m
            | Self::S5 => "aat.depth",
            Self::S3d | Self::S4b5 | Self::S4q => "aat.link",
            Self::S3e | Self::S4i => "aat.expired",
            Self::S3f | Self::S3g | Self::S3h | Self::S4h | Self::S4j | Self::S4k | Self::S4l => {
                "aat.lifetime"
            }
            Self::S3j | Self::S4b1 => "aat.malformed",
            Self::S3k | Self::S4c => "aat.wrong_issuer",
            Self::S3l | Self::S4b2 => "aat.bad_cnf",
            Self::S3m | Self::S4b3 | Self::S4n | Self::S6a => "aat.bad_authorization_details",
            Self::S3n | Self::S4o => "aat.bad_constraint",
            Self::S4p1 | Self::S4p2 | Self::S4p3 | Self::S4p4 => "aat.not_attenuated",
            Self::S6b => "aat.invocation_denied",
            Self::S6c => "aat.audience",
            Self::S7c => "aat.pop_malformed",
            Self::S7d => "aat.pop_audience",
            Self::S7e | Self::S7f => "aat.pop_mismatch",
            Self::S7g => "aat.pop_stale",
            Self::S7h => "aat.pop_nonce",
            Self::S7i => "aat.pop_replayed",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A verification failure: the §8 step that failed and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AatError {
    step: Step,
    token: Option<usize>,
    reason: &'static str,
}

impl AatError {
    pub(crate) const fn new(step: Step, reason: &'static str) -> Self {
        Self {
            step,
            token: None,
            reason,
        }
    }

    pub(crate) const fn at(step: Step, token: usize, reason: &'static str) -> Self {
        Self {
            step,
            token: Some(token),
            reason,
        }
    }

    /// The §8 step that failed.
    #[must_use]
    pub const fn step(&self) -> Step {
        self.step
    }

    /// The position in the chain of the token that failed, root first, if
    /// the failure is about one token.
    #[must_use]
    pub const fn token(&self) -> Option<usize> {
        self.token
    }

    /// The stable error code. Several steps share a code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.step.code()
    }
}

impl fmt::Display for AatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}: {}", self.step, self.reason)?;
        if let Some(i) = self.token {
            write!(f, " (token {i})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AatError {}

impl ChainError for AatError {
    fn code(&self) -> &'static str {
        self.step.code()
    }
}
