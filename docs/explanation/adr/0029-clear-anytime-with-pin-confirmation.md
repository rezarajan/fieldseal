# ADR 0029: Review until clear; clear at any time with a twice-entered PIN

**Status:** Accepted (2026-10-26, decided by the project lead in architecture review #40) · **Priority:** Must · **Date:** 2026-10-26 · **Supersedes:** [0019](./0019-review-until-clear.md)

**In one line:** Collectors review everything until they clear; clearing is always allowed after entering their PIN twice, and is offered automatically once the authority's receipt arrives.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

[ADR 0019](./0019-review-until-clear.md) allowed clearing only after delivery was confirmed. The project lead decided that a collector must always be able to clear the readable data on a shared device, for example before handing it to someone else, while the default path still waits for the authority's receipt. Clearing is irreversible, so it needs stronger confirmation than a hold gesture.

## Decision

- **Review.** The collector MUST be able to review every record in the local record during a session, with the instrument's field checks, until it is cleared.
- **Clear is always available.** The collector MUST be able to clear the local record through any sequence number at any time, whatever its delivery state.
- **Confirmation by PIN, twice.** Every clear MUST be confirmed by entering the runtime PIN twice, as two separate entries. A mismatch or wrong PIN MUST cancel the clear and count toward PIN lockout. No policy can remove this confirmation (an invariant).
- **Default: wait for the receipt, then offer.** By default the runtime MUST wait for an authority receipt. When a receipt covers records, the runtime MUST offer to clear them ("All work received. Clear it from this device?"), confirmed by the twice-entered PIN, and the offer MUST stay available from then on. The runtime MUST NOT clear without that confirmation.
- **Clearing never loses data.** A clear MUST:
  1. seal a checkpoint record;
  2. delete the local record (the readable copy) through `N`;
  3. delete sealed journal records through `N` **only if** a verified receipt covers them.

  Sealed journal records not yet received MUST be kept, unreadable on the device, until a receipt covers them, and are then deleted without further prompting.
- **Say what will happen.** Before confirmation, the runtime MUST show how many records are being cleared and how many of them the authority hasn't received yet, with the statement that their sealed copies stay on the device until delivered.

## Consequences

- A collector can always remove readable data from a shared device, and still nothing is lost: the sealed copy waits for delivery.
- After a receipt, clearing takes one prompt and two PIN entries.
- A forced close by the authority ([ADR 0016](./0016-tenancies-with-crypto-erase.md)) remains the only way to discard undelivered sealed records.

## Specs

[collection](../../reference/spec/collection.md) · [delivery](../../reference/spec/delivery.md) · [policy](../../reference/spec/policy.md)
