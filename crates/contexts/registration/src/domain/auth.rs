//! Authentication strength at the portal (REG-002, REG-002a).
//!
//! An `IdentityProvider` adapter reports the methods the identity provider asserted (for
//! OIDC, the ID token's `amr` and `acr` claims) and whether it could take them from the
//! provider's own assertion ([`MethodAssurance::FromProvider`]) or only from an
//! intermediary that may have changed them ([`MethodAssurance::Asserted`]). Strength is
//! never inferred from configuration. [`check_authentication`] applies factory policy.

use fieldseal_policy::domain::RegistrationPolicy;

use super::{AccountId, Role};

/// Authentication method references (RFC 8176 `amr` values) that are phishing-resistant:
/// proof of possession of a hardware- or software-secured key (`hwk`, `swk`, which is
/// what FIDO authenticators report), a FIDO authenticator named as such (`fido`), and a
/// smart card (`sc`). Passwords, one-time codes, SMS and push approvals are not.
pub const PHISHING_RESISTANT_AMR: &[&str] = &["hwk", "swk", "fido", "sc"];

/// Authentication context class references that state phishing resistance outright: the
/// OpenID `phr` and `phrh` values.
pub const PHISHING_RESISTANT_ACR: &[&str] = &["phr", "phrh"];

/// Whether the methods an identity provider asserted include a phishing-resistant one
/// (REG-002), from `amr` and `acr` alone.
pub fn phishing_resistant_from_claims(amr: &[String], acr: Option<&str>) -> bool {
    phishing_resistant_with(amr, acr, &[], &[])
}

/// As [`phishing_resistant_from_claims`], for an issuer whose own vocabulary has extra
/// values that mean phishing-resistant (`extra_amr`, `extra_acr`), as the deployment
/// states for that issuer. This widens only what a token's own claims may say; with no
/// claims there is no strength, and nothing is ever inferred from the issuer's identity
/// or from how it is configured (REG-002a). The built-in values always apply.
pub fn phishing_resistant_with(amr: &[String], acr: Option<&str>, extra_amr: &[String], extra_acr: &[String]) -> bool {
    amr.iter().any(|m| PHISHING_RESISTANT_AMR.contains(&m.as_str()) || extra_amr.contains(m))
        || acr.is_some_and(|a| PHISHING_RESISTANT_ACR.contains(&a) || extra_acr.iter().any(|e| e == a))
}

/// Where the reported methods came from (REG-002a).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MethodAssurance {
    /// From the identity provider's own signed assertion, unchanged.
    FromProvider,
    /// Through a broker that may not pass the provider's claims through unchanged: the
    /// adapter reports the methods as `asserted`, and policy must accept that explicitly.
    Asserted,
}

/// How a person authenticated, as reported by the identity provider.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthenticationMethods {
    /// Method names as the provider reports them (for example `hwk`, `pwd`).
    pub methods: Vec<String>,
    /// Whether at least one method was phishing-resistant (REG §IdentityProvider).
    pub phishing_resistant: bool,
    /// Where the methods came from.
    pub assurance: MethodAssurance,
}

/// A person authenticated at the portal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthenticatedPerson {
    /// The provider's stable subject identifier.
    pub account: AccountId,
    /// Roles granted by the provider.
    pub roles: Vec<Role>,
    /// The provider's role or group names as given (matched against
    /// `factory.registration.batchTokens.roles`).
    pub role_names: Vec<String>,
    /// How they authenticated.
    pub authentication: AuthenticationMethods,
}

impl AuthenticatedPerson {
    /// Whether the person holds `role`.
    pub fn has(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

/// What the factory records about a sign-in it relied on (REG-002a): kept on the token and
/// on every registration made with it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthRecord {
    /// The methods reported.
    pub methods: Vec<String>,
    /// Whether one was phishing-resistant.
    pub phishing_resistant: bool,
    /// Whether the methods were only `asserted` (accepted because policy said so).
    pub asserted: bool,
}

/// Why a sign-in is not strong enough for registration.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AuthRefusal {
    /// Policy requires a phishing-resistant method and none was used (REG-002).
    #[error("a phishing-resistant sign-in method is required")]
    PhishingResistantRequired,
    /// The methods were only `asserted` and policy doesn't accept that (REG-002a).
    #[error("authentication methods asserted by a broker are not accepted by policy")]
    AssertedNotAccepted,
}

impl AuthRefusal {
    /// The policy reason code.
    pub fn reason(self) -> &'static str {
        match self {
            Self::PhishingResistantRequired => "phishing-resistant-auth-required",
            Self::AssertedNotAccepted => "asserted-auth-not-accepted",
        }
    }
}

/// Applies factory policy to how a person authenticated (REG-002, REG-002a). `asserted`
/// methods are refused unless policy accepts them explicitly, whatever they claim; then a
/// phishing-resistant method is required when policy says so (the default).
pub fn check_authentication(policy: &RegistrationPolicy, auth: &AuthenticationMethods) -> Result<AuthRecord, AuthRefusal> {
    let asserted = auth.assurance == MethodAssurance::Asserted;
    if asserted && !policy.accept_asserted_auth_methods {
        return Err(AuthRefusal::AssertedNotAccepted);
    }
    if policy.require_phishing_resistant_auth && !auth.phishing_resistant {
        return Err(AuthRefusal::PhishingResistantRequired);
    }
    Ok(AuthRecord { methods: auth.methods.clone(), phishing_resistant: auth.phishing_resistant, asserted })
}
