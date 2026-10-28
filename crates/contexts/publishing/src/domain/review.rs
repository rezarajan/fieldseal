//! Reviews and the approval rules (PUB-010–013, PUB-107). Reviews are data supplied by
//! the review system; this module only decides what they add up to.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::id::{ContentAddress, ReviewerId};

use super::artefact::ArtefactKind;
use super::error::PublishingError;

/// A role the review system grants a reviewer (PUB-013, INS-083): the right to review
/// artefacts of one kind, optionally as the reviewer for one language of an instrument.
///
/// A role with `language: None` makes the holder a reviewer of the kind. A role with a
/// language also makes the holder a reviewer of the kind, and lets them stand as the
/// reviewer for that language.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ReviewerRole {
    /// The artefact kind the role covers.
    pub kind: ArtefactKind,
    /// The language tag the holder reviews, for an instrument's translation review.
    pub language: Option<String>,
}

impl ReviewerRole {
    /// A reviewer of `kind`.
    pub fn of_kind(kind: ArtefactKind) -> Self {
        Self { kind, language: None }
    }

    /// A reviewer of `kind` for `language`.
    pub fn for_language(kind: ArtefactKind, language: &str) -> Self {
        Self { kind, language: Some(language.to_owned()) }
    }
}

/// The roles held by each reviewer, as supplied by the review system.
pub type ReviewerRoles = BTreeMap<ReviewerId, Vec<ReviewerRole>>;

/// What approvals must additionally satisfy: the artefact's kind and the languages whose
/// review is required (PUB-013, INS-083).
#[derive(Clone, Copy, Debug)]
pub struct RoleRules<'a> {
    /// The artefact's kind; reviewers must hold a reviewer role for it.
    pub kind: ArtefactKind,
    /// The roles each reviewer holds. A reviewer absent from the map holds none.
    pub roles: &'a ReviewerRoles,
    /// The languages an instrument declares; each needs a counted reviewer for it. Empty
    /// for every other kind.
    pub languages: &'a [String],
}

/// An immutable source revision, for example a commit ID.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RevisionId(pub String);

/// A reviewer's decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ReviewDecision {
    /// Approved.
    Approve,
    /// Rejected.
    Reject,
}

/// One reviewer's decision on one artefact version, tied to its content address and the
/// exact revision reviewed (PUB-011).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Review {
    /// The artefact reviewed.
    pub address: ContentAddress,
    /// The exact source revision reviewed.
    pub revision: RevisionId,
    /// The pseudonymous reviewer (PUB-107).
    pub reviewer: ReviewerId,
    /// The decision.
    pub decision: ReviewDecision,
}

/// A source snapshot at an immutable revision.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceSnapshot {
    /// The revision.
    pub revision: RevisionId,
    /// The revision's author, pseudonymously.
    pub author: ReviewerId,
    /// The artefact's source document.
    pub document: Vec<u8>,
}

/// Whether a reviewer identifier is pseudonymous: no `@` (an email address), no
/// whitespace and no control characters, at most 128 bytes (PUB-107, PUB-108). The mapping
/// to a person lives only in the private key-holder registry (TRU-092).
pub fn is_pseudonymous(reviewer: &ReviewerId) -> bool {
    let s = reviewer.as_str();
    s.len() <= 128 && !s.contains('@') && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The approvals that count for one artefact version (PUB-010–012): distinct reviewers who
/// approved this exact address and revision, without the author unless policy allows it.
/// Any rejection of that address and revision blocks the version, as does a reviewer who
/// is not pseudonymous (PUB-107).
///
/// Only reviewers who hold a reviewer role for the artefact's kind count, and only their
/// rejections block (PUB-013); a review by anyone else is ignored, so a stranger can't block
/// a version. When languages are required, each needs a counted approver who holds the
/// role for that language (INS-083).
///
/// Returns the counted reviewers, sorted, or why they don't reach `required`.
pub fn counted_approvals(
    reviews: &[Review],
    address: &ContentAddress,
    revision: &RevisionId,
    author: &ReviewerId,
    author_may_approve: bool,
    required: u64,
    rules: RoleRules<'_>,
) -> Result<Vec<ReviewerId>, PublishingError> {
    let holds = |who: &ReviewerId, language: Option<&str>| {
        rules.roles.get(who).is_some_and(|rs| {
            rs.iter().any(|r| r.kind == rules.kind && language.is_none_or(|l| r.language.as_deref() == Some(l)))
        })
    };
    let mut approvers = BTreeSet::new();
    for r in reviews.iter().filter(|r| &r.address == address && &r.revision == revision) {
        if !is_pseudonymous(&r.reviewer) {
            return Err(PublishingError::IdentityAttribute(r.reviewer.as_str().to_owned()));
        }
        if !holds(&r.reviewer, None) {
            continue;
        }
        match r.decision {
            ReviewDecision::Reject => return Err(PublishingError::Rejected(r.reviewer.clone())),
            ReviewDecision::Approve if &r.reviewer == author && !author_may_approve => {}
            ReviewDecision::Approve => {
                approvers.insert(r.reviewer.clone());
            }
        }
    }
    let have = approvers.len() as u64;
    let need = required.max(1);
    if have < need {
        return Err(PublishingError::NotEnoughApprovals { have, need });
    }
    if let Some(language) = rules.languages.iter().find(|l| !approvers.iter().any(|a| holds(a, Some(l)))) {
        return Err(PublishingError::MissingLanguageReview(language.clone()));
    }
    Ok(approvers.into_iter().collect())
}
