//! Driven ports owned by the Registration context (`docs/reference/spec/registration.md` §4).
//!
//! Registration also uses ports owned by inner contexts: Trust's `KeyCustody` (the spec's
//! `Signer` and `Unsealer`, with the `registration` purpose), `AttestationVerifier`,
//! `AuthorityClock` and `RandomSource` (the spec's `NonceSource`), and Policy's
//! `PolicyEngine` and `DecisionLog`.

use std::collections::BTreeMap;

use fieldseal_kernel::id::{Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

use crate::domain::{
    AccessToken, Account, AccountId, AuthenticatedPerson, DeviceId, IssuedToken, RegisteredDevice, TenancyRecord,
    TokenSecret,
};

/// Errors from [`IdentityProvider`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The sign-in didn't authenticate anyone: a bad signature, wrong issuer, audience or
    /// nonce, an expired token, or a callback that doesn't match the pending sign-in.
    #[error("not authenticated: {0}")]
    NotAuthenticated(String),
    /// The provider is unavailable.
    #[error("identity provider: {0}")]
    Unavailable(String),
}

/// The start of a sign-in: where to send the browser, and the state the portal keeps
/// server-side until the provider redirects back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignInStart {
    /// The provider's authorisation URL to redirect to.
    pub redirect_to: String,
    /// What the portal keeps until the callback.
    pub pending: PendingSignIn,
}

/// A sign-in in progress. `state` comes back in the callback; `secret` is adapter-specific
/// (for OIDC, the PKCE verifier and the nonce) and never leaves the portal.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingSignIn {
    /// The value the provider echoes in the callback (CSRF protection).
    pub state: String,
    /// Adapter-specific secret state.
    pub secret: Vec<u8>,
}

impl core::fmt::Debug for PendingSignIn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingSignIn").field("state", &self.state).finish_non_exhaustive()
    }
}

/// Authenticates people at the portal (REG-002).
///
/// Contract (checked by [`crate::contract::identity_provider_contract`]): returns a stable
/// subject identifier, the methods used and the roles; reports whether a phishing-resistant
/// method was used, taken from the provider's own assertion and never from configuration,
/// or reports the methods as `asserted` (REG-002a); never authenticates a callback it
/// couldn't verify, or one that doesn't match the pending sign-in. The runtime never uses
/// this port (REG-001).
pub trait IdentityProvider {
    /// Starts a sign-in that returns to `redirect_uri`.
    fn start_sign_in(&self, redirect_uri: &str) -> Result<SignInStart, IdentityError>;

    /// Completes a sign-in from the provider's callback parameters.
    fn finish_sign_in(
        &self,
        pending: &PendingSignIn,
        callback: &BTreeMap<String, String>,
    ) -> Result<AuthenticatedPerson, IdentityError>;
}

/// Why a token couldn't be consumed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// No token has this secret.
    #[error("unknown token")]
    Unknown,
    /// The token has been used up.
    #[error("token already used")]
    Used,
    /// The token expired, by the factory's clock (REG-006).
    #[error("token expired")]
    Expired,
}

/// Errors from [`RegistryStore`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryStoreError {
    /// A token with this secret already exists.
    #[error("duplicate token")]
    DuplicateToken,
    /// An update would remove keys from a tenancy's history.
    #[error("keys are never deleted from a tenancy's history")]
    HistoryViolation,
    /// No such record.
    #[error("not found")]
    NotFound,
    /// The store failed.
    #[error("registry store: {0}")]
    Backend(String),
}

/// A one-time challenge the factory issued to a tenancy (posture nonces, REG-071).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssuedNonce {
    /// The nonce.
    pub nonce: Nonce,
    /// The tenancy it was issued to.
    pub tenancy: TenancyId,
    /// When it stops being accepted.
    pub expires_at: AuthorityTime,
}

/// Durable storage for accounts, devices, tokens and tenancies.
///
/// Contract (checked by [`crate::contract::registry_store_contract`]): token consumption is
/// atomic, so a single-use token registers at most one tenancy even under concurrent
/// requests; expiry is judged against the time the caller passes, which comes from the
/// factory's clock; tenancy updates can't remove keys from history; nonces and PoP `jti`s
/// are single use, atomically.
pub trait RegistryStore {
    /// Stores a newly issued token.
    fn put_token(&self, token: &IssuedToken) -> Result<(), RegistryStoreError>;

    /// Reads a token and how many of its uses remain, without using one.
    fn token(&self, secret: &TokenSecret) -> Result<Option<(IssuedToken, u32)>, RegistryStoreError>;

    /// Atomically uses one of the token's uses at `now`, returning the token.
    fn consume_token(&self, secret: &TokenSecret, now: AuthorityTime) -> Result<IssuedToken, TokenError>;

    /// Creates or updates an account.
    fn put_account(&self, account: &Account) -> Result<(), RegistryStoreError>;

    /// An account by ID.
    fn account(&self, id: &AccountId) -> Result<Option<Account>, RegistryStoreError>;

    /// Creates or updates a tenancy.
    fn put_tenancy(&self, tenancy: &TenancyRecord) -> Result<(), RegistryStoreError>;

    /// A tenancy by ID.
    fn tenancy(&self, id: &TenancyId) -> Result<Option<TenancyRecord>, RegistryStoreError>;

    /// A tenancy by its export handle.
    fn tenancy_by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyRecord>, RegistryStoreError>;

    /// Every tenancy of an account.
    fn tenancies_of(&self, account: &AccountId) -> Result<Vec<TenancyRecord>, RegistryStoreError>;

    /// Creates or updates a device.
    fn put_device(&self, device: &RegisteredDevice) -> Result<(), RegistryStoreError>;

    /// A device by ID.
    fn device(&self, id: &DeviceId) -> Result<Option<RegisteredDevice>, RegistryStoreError>;

    /// Every device of an account.
    fn devices_of(&self, account: &AccountId) -> Result<Vec<RegisteredDevice>, RegistryStoreError>;

    /// Stores a one-time nonce.
    fn put_nonce(&self, nonce: &IssuedNonce) -> Result<(), RegistryStoreError>;

    /// Atomically takes a nonce issued to `tenancy` that hasn't expired at `now`; `false` if
    /// there is none (unknown, used, expired or for another tenancy).
    fn take_nonce(&self, nonce: &Nonce, tenancy: &TenancyId, now: AuthorityTime) -> Result<bool, RegistryStoreError>;

    /// Atomically records a PoP token's `jti` for `tenancy` until `until`; `false` if it was
    /// already recorded and hasn't lapsed at `now` (a replay, WIRE-171).
    fn record_jti(&self, tenancy: &TenancyId, jti: &[u8; 16], until: AuthorityTime, now: AuthorityTime)
    -> Result<bool, RegistryStoreError>;

    /// Stores an access token.
    fn put_access_token(&self, token: &AccessToken) -> Result<(), RegistryStoreError>;

    /// An access token by value.
    fn access_token(&self, value: &[u8; 32]) -> Result<Option<AccessToken>, RegistryStoreError>;
}

/// Errors from [`ReceivedProgress`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProgressError {
    /// The source is unavailable.
    #[error("received-progress source: {0}")]
    Unavailable(String),
}

/// What the authority has received from a tenancy, for setting a cutoff (REG-062).
///
/// Contract: returns the highest `seq` intake has received for the tenancy, or `None` if
/// nothing has arrived. Never guesses.
pub trait ReceivedProgress {
    /// The highest received `seq`.
    fn highest_received(&self, tenancy: &TenancyId) -> Result<Option<Seq>, ProgressError>;
}

/// Whether a device serial belongs to the deployment's fleet (REG-016).
///
/// Contract: answers from the fleet registry only; an unknown serial is `false`.
pub trait FleetRegistry {
    /// Whether the fleet registry lists `serial`.
    fn knows(&self, serial: &str) -> bool;
}

/// An event shown in the portal's device list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PortalEvent {
    /// A device was registered to the account.
    DeviceRegistered(DeviceId),
    /// A device was marked lost.
    DeviceMarkedLost(DeviceId),
    /// A registration is held for review.
    RegistrationHeld(TenancyId),
}

/// Errors from [`Notifier`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifierError {
    /// The notification couldn't be delivered.
    #[error("notification not delivered: {0}")]
    Undelivered(String),
}

/// Optional: shows events to an account in the portal.
///
/// Contract: no security property may depend on it; callers MUST treat a failure as
/// non-fatal.
pub trait Notifier {
    /// Shows `event` to `account`.
    fn notify(&self, account: &AccountId, event: &PortalEvent) -> Result<(), NotifierError>;
}
