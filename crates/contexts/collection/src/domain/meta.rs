//! What the runtime persists about a tenancy in device-encrypted storage (COL-008): keys by
//! reference, the wrapped session secret, the chain head, checkpoints and delivery state.
//! It holds no names, item values or PIN-derived values (COL-052, TRU-072): the PIN check
//! is an entry encrypted under the session key, which needs the hardware-wrapped secret as
//! well as the PIN.

use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::{Digest, Fingerprint, KeyId, TenancyHandle, TenancyId};
use fieldseal_kernel::structure::{Fields, expect_bytes, expect_bytes_n, expect_uint};
use fieldseal_trust::domain::KeyHandle;

use super::{HashParams, OperationKind, TenancyState};

fn bad(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

fn state_str(s: TenancyState) -> &'static str {
    match s {
        TenancyState::Local => "local",
        TenancyState::Registered => "registered",
        TenancyState::Closing => "closing",
        TenancyState::Closed => "closed",
        TenancyState::Erased => "erased",
    }
}

fn parse_state(t: &str) -> Result<TenancyState, WireError> {
    Ok(match t {
        "local" => TenancyState::Local,
        "registered" => TenancyState::Registered,
        "closing" => TenancyState::Closing,
        "closed" => TenancyState::Closed,
        "erased" => TenancyState::Erased,
        _ => return Err(bad("unknown tenancy state")),
    })
}

/// A checkpoint the device sealed: `(cleared_through, hash_at)`.
pub type ClearedPoint = (u64, Digest);

/// The persisted tenancy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenancyMeta {
    /// The lifecycle state.
    pub state: TenancyState,
    /// The tenancy ID: SHA-256 of the signing public key.
    pub tenancy: TenancyId,
    /// The signing key.
    pub sign: KeyHandle,
    /// The agreement key.
    pub agree: KeyHandle,
    /// The session-wrapping key.
    pub wrap: KeyHandle,
    /// The signing public key (key history index 0).
    pub sign_pub: P256PublicKey,
    /// The agreement public key.
    pub agree_pub: P256PublicKey,
    /// Content addresses of the attestation evidence.
    pub evidence: Vec<Digest>,
    /// The session secret, wrapped by `wrap`.
    pub wrapped_secret: Vec<u8>,
    /// The PIN hash salt.
    pub pin_salt: [u8; 16],
    /// An entry encrypted under the session key, to check a PIN.
    pub pin_check: Vec<u8>,
    /// The runtime build's release anchor.
    pub build_anchor: Digest,
    /// The authority record key payloads are sealed to.
    pub record_key: [u8; 32],
    /// Its key ID.
    pub period: KeyId,
    /// The export handle.
    pub handle: TenancyHandle,
    /// The tenancy certificate's content address, once registered.
    pub certificate: Option<Digest>,
    /// The collection window, once registered: `(not_before, not_after)`.
    pub window: Option<(u64, u64)>,
    /// The latest record: `(seq, record hash)`.
    pub head: Option<(u64, Digest)>,
    /// Anchors chained into the journal, in order (the build anchor first).
    pub anchors: Vec<Digest>,
    /// Anchors seen but not yet chained (a receipt applied without a session).
    pub pending_anchors: Vec<(u8, Digest, u64)>,
    /// Checkpoints sealed.
    pub cleared: Vec<ClearedPoint>,
    /// Highest `seq` a verified receipt covers, with the receipt's content address.
    pub received: Option<(u64, Digest)>,
    /// Highest `seq` saved to local or removable storage and read back.
    pub saved: Option<u64>,
    /// Highest `seq` handed over to an opaque destination.
    pub handed_over: Option<u64>,
    /// Highest journal `seq` deleted under a receipt.
    pub journal_deleted_through: Option<u64>,
    /// Instruments records were made with.
    pub instruments: Vec<Fingerprint>,
    /// The runtime policy in use, if a bundle carried one.
    pub policy: Option<Digest>,
    /// Encryptions made under the session key (WIRE-082).
    pub encryptions: u64,
    /// The latest posture findings, by restriction name and state (PLAT-043).
    pub posture: Vec<(String, String)>,
    /// The PIN hash parameters, fixed when the tenancy was created.
    pub argon: HashParams,
    /// Wrong PINs before the first wait (runtime policy).
    pub failures_before_lockout: u64,
    /// The escalating waits, in milliseconds (runtime policy).
    pub lockout_steps_ms: Vec<u64>,
}

fn opt_digest(v: Option<Value>) -> Result<Option<Digest>, WireError> {
    v.map(|v| expect_bytes_n::<32>(v).map(Digest::from)).transpose()
}

fn pair(v: Value) -> Result<(u64, Digest), WireError> {
    match v {
        Value::Array(a) if a.len() == 2 => {
            let mut it = a.into_iter();
            let n = expect_uint(it.next().expect("two"))?;
            let d = Digest::from(expect_bytes_n::<32>(it.next().expect("two"))?);
            Ok((n, d))
        }
        _ => Err(bad("expected [uint, hash]")),
    }
}

fn pair_value(n: u64, d: &Digest) -> Value {
    Value::Array(vec![Value::Int(i128::from(n)), Value::Bytes(d.as_bytes().to_vec())])
}

impl TenancyMeta {
    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let b = |x: &[u8]| Value::Bytes(x.to_vec());
        let u = |n: u64| Value::Int(i128::from(n));
        let t = |s: &str| Value::Text(s.to_owned());
        let mut e: Vec<(&str, Value)> = vec![
            ("state", t(state_str(self.state))),
            ("tenancy", b(self.tenancy.as_bytes())),
            ("sign", t(&self.sign.0)),
            ("agree", t(&self.agree.0)),
            ("wrap", t(&self.wrap.0)),
            ("sign_pub", b(self.sign_pub.as_bytes())),
            ("agree_pub", b(self.agree_pub.as_bytes())),
            ("evidence", Value::Array(self.evidence.iter().map(|d| b(d.as_bytes())).collect())),
            ("wrapped_secret", b(&self.wrapped_secret)),
            ("pin_salt", b(&self.pin_salt)),
            ("pin_check", b(&self.pin_check)),
            ("build_anchor", b(self.build_anchor.as_bytes())),
            ("record_key", b(&self.record_key)),
            ("period", b(self.period.as_bytes())),
            ("handle", b(self.handle.as_bytes())),
            ("anchors", Value::Array(self.anchors.iter().map(|d| b(d.as_bytes())).collect())),
            (
                "pending_anchors",
                Value::Array(
                    self.pending_anchors
                        .iter()
                        .map(|(k, d, time)| Value::Array(vec![u(u64::from(*k)), b(d.as_bytes()), u(*time)]))
                        .collect(),
                ),
            ),
            ("cleared", Value::Array(self.cleared.iter().map(|(n, d)| pair_value(*n, d)).collect())),
            ("instruments", Value::Array(self.instruments.iter().map(|f| b(f.as_bytes())).collect())),
            ("encryptions", u(self.encryptions)),
            ("argon", Value::Array(vec![u(u64::from(self.argon.memory_kib)), u(u64::from(self.argon.iterations)), u(u64::from(self.argon.parallelism))])),
            ("failures_before_lockout", u(self.failures_before_lockout)),
            ("lockout_steps_ms", Value::Array(self.lockout_steps_ms.iter().map(|n| u(*n)).collect())),
            (
                "posture",
                Value::Array(self.posture.iter().map(|(r, s)| Value::Array(vec![t(r), t(s)])).collect()),
            ),
        ];
        if let Some(c) = &self.certificate {
            e.push(("certificate", b(c.as_bytes())));
        }
        if let Some((nb, na)) = self.window {
            e.push(("window", Value::Array(vec![u(nb), u(na)])));
        }
        if let Some((n, d)) = &self.head {
            e.push(("head", pair_value(*n, d)));
        }
        if let Some((n, d)) = &self.received {
            e.push(("received", pair_value(*n, d)));
        }
        if let Some(n) = self.saved {
            e.push(("saved", u(n)));
        }
        if let Some(n) = self.handed_over {
            e.push(("handed_over", u(n)));
        }
        if let Some(n) = self.journal_deleted_through {
            e.push(("journal_deleted_through", u(n)));
        }
        if let Some(p) = &self.policy {
            e.push(("policy", b(p.as_bytes())));
        }
        cbor::encode(&cbor::map(e)).expect("encodable")
    }

    /// Reads the stored tenancy.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        let digests = |v: Vec<Value>| v.into_iter().map(|d| expect_bytes_n::<32>(d).map(Digest::from)).collect::<Result<Vec<_>, _>>();
        let p256 = |b: [u8; 65]| P256PublicKey::from_bytes(&b).map_err(|_| bad("not a P-256 key"));
        let text = |v: Value| match v {
            Value::Text(t) => Ok(t),
            _ => Err(bad("expected text")),
        };
        let meta = Self {
            state: parse_state(&f.text("state")?)?,
            tenancy: TenancyId::from(f.bytes_n::<32>("tenancy")?),
            sign: KeyHandle(f.text("sign")?),
            agree: KeyHandle(f.text("agree")?),
            wrap: KeyHandle(f.text("wrap")?),
            sign_pub: p256(f.bytes_n::<65>("sign_pub")?)?,
            agree_pub: p256(f.bytes_n::<65>("agree_pub")?)?,
            evidence: digests(f.array("evidence")?)?,
            wrapped_secret: f.bytes("wrapped_secret")?,
            pin_salt: f.bytes_n::<16>("pin_salt")?,
            pin_check: f.bytes("pin_check")?,
            build_anchor: Digest::from(f.bytes_n::<32>("build_anchor")?),
            record_key: f.bytes_n::<32>("record_key")?,
            period: KeyId::from(f.bytes_n::<16>("period")?),
            handle: TenancyHandle::from(f.bytes_n::<16>("handle")?),
            certificate: opt_digest(f.take_opt("certificate"))?,
            window: match f.take_opt("window") {
                Some(Value::Array(a)) if a.len() == 2 => {
                    let mut it = a.into_iter();
                    Some((expect_uint(it.next().expect("two"))?, expect_uint(it.next().expect("two"))?))
                }
                Some(_) => return Err(bad("window is [uint, uint]")),
                None => None,
            },
            head: f.take_opt("head").map(pair).transpose()?,
            anchors: digests(f.array("anchors")?)?,
            pending_anchors: f
                .array("pending_anchors")?
                .into_iter()
                .map(|v| match v {
                    Value::Array(a) if a.len() == 3 => {
                        let mut it = a.into_iter();
                        let k = u8::try_from(expect_uint(it.next().expect("three"))?).map_err(|_| bad("anchor kind"))?;
                        let d = Digest::from(expect_bytes_n::<32>(it.next().expect("three"))?);
                        Ok((k, d, expect_uint(it.next().expect("three"))?))
                    }
                    _ => Err(bad("pending anchor is [kind, hash, time]")),
                })
                .collect::<Result<Vec<_>, WireError>>()?,
            cleared: f.array("cleared")?.into_iter().map(pair).collect::<Result<Vec<_>, _>>()?,
            received: f.take_opt("received").map(pair).transpose()?,
            saved: f.take_opt("saved").map(expect_uint).transpose()?,
            handed_over: f.take_opt("handed_over").map(expect_uint).transpose()?,
            journal_deleted_through: f.take_opt("journal_deleted_through").map(expect_uint).transpose()?,
            instruments: f
                .array("instruments")?
                .into_iter()
                .map(|v| expect_bytes_n::<32>(v).map(Fingerprint::from))
                .collect::<Result<Vec<_>, _>>()?,
            policy: opt_digest(f.take_opt("policy"))?,
            encryptions: f.uint("encryptions")?,
            posture: f
                .array("posture")?
                .into_iter()
                .map(|v| match v {
                    Value::Array(a) if a.len() == 2 => {
                        let mut it = a.into_iter();
                        Ok((text(it.next().expect("two"))?, text(it.next().expect("two"))?))
                    }
                    _ => Err(bad("posture finding is [name, state]")),
                })
                .collect::<Result<Vec<_>, WireError>>()?,
            argon: {
                let a = f.array("argon")?.into_iter().map(expect_uint).collect::<Result<Vec<_>, _>>()?;
                let n = |i: usize| a.get(i).and_then(|v| u32::try_from(*v).ok()).ok_or(bad("argon is [m, t, p]"));
                HashParams { memory_kib: n(0)?, iterations: n(1)?, parallelism: n(2)? }
            },
            failures_before_lockout: f.uint("failures_before_lockout")?,
            lockout_steps_ms: f.array("lockout_steps_ms")?.into_iter().map(expect_uint).collect::<Result<Vec<_>, _>>()?,
        };
        f.finish()?;
        Ok(meta)
    }

    /// The next record's `seq`.
    pub fn next_seq(&self) -> u64 {
        self.head.map_or(0, |(s, _)| s + 1)
    }

    /// The wait after `failures` consecutive wrong PINs (COL-023): none until
    /// `failures_before_lockout`, then each step in turn, staying at the last.
    pub fn lockout_delay_ms(&self, failures: u64) -> Option<u64> {
        if failures < self.failures_before_lockout {
            return None;
        }
        let i = usize::try_from(failures - self.failures_before_lockout).unwrap_or(usize::MAX);
        self.lockout_steps_ms.get(i).or(self.lockout_steps_ms.last()).copied()
    }

    /// The highest `seq` cleared from the local record.
    pub fn cleared_through(&self) -> Option<u64> {
        self.cleared.iter().map(|(s, _)| *s).max()
    }
}

/// Persisted progress of a multi-step operation (COL-092).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Marker {
    /// The operation.
    pub kind: OperationKind,
    /// The last step completed.
    pub step: u32,
    /// The `seq` the operation's record takes.
    pub seq: u64,
    /// For a clear, the `seq` cleared through; otherwise unused.
    pub through: u64,
    /// For a clear, the journal deletion limit; for a close, the outbox entry name.
    pub extra: Option<Vec<u8>>,
}

fn kind_str(k: OperationKind) -> &'static str {
    match k {
        OperationKind::Seal => "seal",
        OperationKind::Clear => "clear",
        OperationKind::EndTenancy => "end-tenancy",
        OperationKind::ApplyCloseCertificate => "apply-close-certificate",
        OperationKind::Export => "export",
    }
}

impl Marker {
    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = vec![
            ("kind", Value::Text(kind_str(self.kind).to_owned())),
            ("step", Value::Int(i128::from(self.step))),
            ("seq", Value::Int(i128::from(self.seq))),
            ("through", Value::Int(i128::from(self.through))),
        ];
        if let Some(x) = &self.extra {
            e.push(("extra", Value::Bytes(x.clone())));
        }
        cbor::encode(&cbor::map(e)).expect("encodable")
    }

    /// Reads a marker.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        let kind = match f.text("kind")?.as_str() {
            "seal" => OperationKind::Seal,
            "clear" => OperationKind::Clear,
            "end-tenancy" => OperationKind::EndTenancy,
            "apply-close-certificate" => OperationKind::ApplyCloseCertificate,
            "export" => OperationKind::Export,
            _ => return Err(bad("unknown operation")),
        };
        let m = Self {
            kind,
            step: u32::try_from(f.uint("step")?).map_err(|_| bad("step"))?,
            seq: f.uint("seq")?,
            through: f.uint("through")?,
            extra: f.take_opt("extra").map(expect_bytes).transpose()?,
        };
        f.finish()?;
        Ok(m)
    }
}
