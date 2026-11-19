//! The scope grammar and covering relation (§4.1).

/// The form of a scope value, classified by its bytes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    Literal,
    Wildcard,
    Opaque,
}

/// `segment = lower *(lower / digit / "_" / "-")`.
fn is_segment(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// `opaque-scope = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )`: the RFC 6749
/// scope-token without `*`.
fn is_opaque(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x29 | 0x2B..=0x5B | 0x5D..=0x7E))
}

/// Classifies `scope` as literal, then wildcard, then opaque, in that order.
/// `None` means the value matches none of the three and is invalid.
pub(crate) fn classify(scope: &str) -> Option<Form> {
    let mut segments = scope.split('.');
    let literal = segments.clone().count() >= 2 && segments.all(is_segment);
    if literal {
        return Some(Form::Literal);
    }
    if let Some(prefix) = scope.strip_suffix(".*")
        && prefix.split('.').all(is_segment)
    {
        return Some(Form::Wildcard);
    }
    is_opaque(scope).then_some(Form::Opaque)
}

/// Whether `held` covers `requested`: a wildcard covers any literal or
/// wildcard that begins with it minus the final `*`; anything else covers
/// only an identical value. An invalid value covers and is covered by
/// nothing.
pub(crate) fn covers(held: &str, requested: &str) -> bool {
    let (Some(held_form), Some(requested_form)) = (classify(held), classify(requested)) else {
        return false;
    };
    if held_form == Form::Wildcard {
        let stem = &held[..held.len() - 1];
        return requested_form != Form::Opaque && requested.starts_with(stem);
    }
    held == requested
}

#[cfg(test)]
mod tests {
    use super::{Form, classify, covers};

    #[test]
    fn classification_follows_the_draft_examples() {
        assert_eq!(classify("crm.read"), Some(Form::Literal));
        assert_eq!(classify("crm.*"), Some(Form::Wildcard));
        assert_eq!(classify("crm.x.*"), Some(Form::Wildcard));
        assert_eq!(classify("User.Read"), Some(Form::Opaque));
        assert_eq!(classify("openid"), Some(Form::Opaque));
        assert_eq!(classify("repo:status"), Some(Form::Opaque));
        for invalid in [
            "*",
            "crm.re*",
            "crm.*.read",
            "User.*",
            "crm.read\n",
            "",
            "a b",
        ] {
            assert_eq!(classify(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn covering() {
        assert!(covers("crm.*", "crm.read"));
        assert!(covers("crm.*", "crm.x.y.z"));
        assert!(covers("crm.*", "crm.x.*"));
        assert!(!covers("crm.*", "crm"));
        assert!(!covers("crm.*", "crmx.read"));
        assert!(!covers("drive.*", "drive.Read"));
        assert!(!covers("drive.Read", "drive.*"));
        assert!(covers("User.Read", "User.Read"));
        assert!(!covers("User.Read", "user.read"));
        assert!(!covers("crm.read", "crm.*"));
    }
}
