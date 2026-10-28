# End-to-end flows

Every persona and every flow, from the root ceremony to the data platform. Development uses software keys and unattested devices; production uses hardware-backed custody and attested devices.

```mermaid
sequenceDiagram
    autonumber
    actor Cust as Custodians
    actor Author
    actor Rev as Reviewers
    actor Pub as Publishers
    participant Build as Builder
    participant Log as Transparency log
    actor Op as Operator
    participant IdP as Identity provider
    participant Fac as Factory
    actor Col as Collector
    participant Dev as Device
    actor Subj as Subject
    participant Int as Intake
    actor DC as Data custodian
    participant DP as Data platform
    actor Aud as Auditor

    rect rgba(13,122,95,0.08)
    Note over Cust,Fac: 1. Trust
    Cust->>Cust: Root ceremony, 2 of 3 custodians and a witness
    Fac->>Cust: CSRs with proof of possession (registration, receipt, record, factory keys)
    Build->>Cust: CSR (builder key)
    Pub->>Cust: CSRs (publisher keys)
    Cust-->>Fac: Purpose-key certificates
    Cust->>Log: Pin the log origin and its key
    Cust-->>Fac: Trust bundle (roots, certificates, attestation roots, log pin)
    end

    rect rgba(2,132,199,0.08)
    Note over Author,Fac: 2. Publishing
    Author->>Build: Compact survey, layouts, i18n catalogues
    Build->>Build: Expand to the canonical instrument, validate strictly, sign provenance
    Rev-->>Build: Approvals, one reviewer per translated language
    Pub-->>Build: Publisher signatures, 2 of 3
    Build->>Log: Append each signature entry
    Log-->>Build: Inclusion proofs, checkpoint, authority time token
    Build->>Fac: Place the publication in the register
    end

    rect rgba(217,119,6,0.08)
    Note over Op,Fac: 3. Operator sign-in
    Op->>Fac: Open the portal
    Fac->>IdP: Authorization code with PKCE, acr requested
    IdP->>Op: Passkey (WebAuthn, user verification)
    IdP-->>Fac: ID token with acr phr
    Fac-->>Op: Phishing-resistant session (a username-only session cannot register devices)
    end

    rect rgba(124,58,237,0.08)
    Note over Op,Dev: 4. Device setup and registration
    Col->>Dev: Create the tenancy and set a PIN
    Dev->>Dev: Generate signing, agreement and wrapping keys (attestation evidence on hardware)
    Op->>Fac: Get a registration token
    Fac-->>Op: One-time token, minutes to live
    Op->>Col: Hand over the token
    Col->>Dev: Enter the token
    Dev->>Dev: Build the sealed request (keys, evidence, proof of possession), show four words
    Dev->>Fac: Submit the sealed request
    Fac-->>Op: Pending request with the same four words
    Op->>Col: Compare the four words
    Op->>Fac: Confirm
    Fac->>Fac: Register the tenancy, assign its cohorts
    Dev->>Fac: Poll the status, fetch the tenancy certificate (PoP)
    Fac-->>Dev: Tenancy certificate
    end

    rect rgba(13,122,95,0.08)
    Note over Col,Int: 5. Loading a survey
    Col->>Dev: Choose a survey (food, water, any published)
    Dev->>Fac: Request its bundle (PoP)
    Fac->>Fac: Release by policy (attested key, or the development allowance), keep only the roster fields the survey reads
    Fac->>Int: Record the issued rosters and their consent states
    Fac-->>Dev: Bundle sealed to the device's agreement key and signed
    Dev->>Dev: Verify in order: signature, publisher threshold, log inclusion and time token, roster generation, then decrypt
    opt Load another survey
    Col->>Dev: Choose again, the same flow
    end
    end

    rect rgba(2,132,199,0.08)
    Note over Col,Subj: 6. Collection
    Col->>Dev: Unlock with the PIN
    Col->>Subj: Visit
    alt Consent unknown on the roster
    Subj-->>Col: Gives consent
    Col->>Dev: Attest consent (basis, statement, evidence)
    else Consent refused
    Dev-->>Col: Nothing can be recorded
    end
    Col->>Dev: Capture answers, every limit enforced at entry, rules checked by the core
    Dev->>Dev: Review, acknowledge unanswered items, hold to seal
    Dev->>Dev: Record sealed to the record key, signed, chained in the journal
    opt Resurvey or correction
    Col->>Dev: Changed answers only, sealed as a new record
    end
    end

    rect rgba(217,119,6,0.08)
    Note over Col,Int: 7. Delivery
    Col->>Dev: Hand over the records
    Dev->>Int: Receiver challenge
    Int-->>Dev: Answer signed by the receiver key
    Dev->>Int: Upload the export (PoP)
    Int->>Int: Gate: authenticity, chain, decrypt, schema, consent, duplicates
    Int-->>Dev: A signed receipt per part
    Dev->>Dev: Verify every receipt against the trust bundle
    Col->>Dev: Clear, PIN twice, erases what receipts cover
    alt No network
    Dev-->>Col: Export file or QR sequence, parity included
    Col->>Int: Carry the file, the same gate and receipts
    end
    end

    rect rgba(124,58,237,0.08)
    Note over Int,DP: 8. Intake and the data platform
    Int->>Int: Land long-format rows, the loss ledger and field-check findings
    Int->>DC: Held consent cases
    DC-->>Int: Accept or refuse, and the rows follow
    Int->>DP: Landed files and the data contract (no derived values)
    end

    rect rgba(220,38,38,0.07)
    Note over Cust,Dev: 9. Lifecycle
    Pub->>Log: Withdraw an artefact, 2 of 3
    Fac->>Dev: The next bundle carries the withdrawal, new records refused, review and export still allowed
    Cust->>Fac: Rotate or revoke keys, new trust bundle
    Op->>Fac: Mark a device lost, revoke its tenancy
    Col->>Dev: Reset this device, keys and records erased
    Dev->>Fac: An unknown tenancy (a reset factory) means register again
    end

    rect rgba(2,132,199,0.08)
    Note over Aud,Fac: 10. Audit
    Aud->>Log: Checkpoint and consistency proofs
    Aud->>Fac: List, fetch and verify every publication against the trust bundle
    end
```
