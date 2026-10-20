//! What a directory or mirror keeps per (directory, name), even after the
//! name's listings are withdrawn, expire or are revoked (SPEC §13.2.2).

use super::card::SignedListing;
use super::withdrawal::Withdrawal;
use crate::error::{Error, Result};

/// The per-name state that decides which listings a directory accepts
/// (SPEC §13.2.2, §13.2.3, §13.2.5). Keep it for as long as the name
/// exists, **including after** its listing is withdrawn, its token expires
/// or is revoked, or it is tombstoned: otherwise a superseded key could
/// take the name back once nothing is stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameRecord {
    /// The newest token `issued_at` ever accepted for the name, and the
    /// identity it was issued to.
    pub high_water: Option<(u64, String)>,
    /// Per identity, the highest `seq` a withdrawal of the name tombstoned.
    pub tombstones: Vec<(String, u64)>,
}

impl NameRecord {
    /// Whether `listing` may be published for this name, given the listing
    /// `stored` for it now (if any). In order:
    ///
    /// 1. its token is no older than the name's high-water mark; on a tie
    ///    only the identity that set the mark passes;
    /// 2. it replaces `stored` ([`SignedListing::replaces`]);
    /// 3. no tombstone of its own identity covers its `seq`.
    ///
    /// The token's own checks (signature, pinning, expiry, revocation) and
    /// the time checks are separate.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] of kind `superseded`, naming the rule.
    pub fn admits(&self, listing: &SignedListing, stored: Option<&SignedListing>) -> Result<()> {
        let issued = listing.token().grant.issued_at;
        if let Some((mark, holder)) = &self.high_water {
            let newer = issued > *mark;
            let tie = issued == *mark && *holder == listing.params().identity;
            if !newer && !tie {
                return Err(Error::InvalidListing("token older than the name's newest"));
            }
        }
        if let Some(stored) = stored
            && !listing.replaces(stored)
        {
            return Err(Error::InvalidListing("does not replace the stored listing"));
        }
        let identity = &listing.params().identity;
        if self
            .tombstones
            .iter()
            .any(|(id, seq)| listing.tombstoned_by(id, *seq) && id == identity)
        {
            return Err(Error::InvalidListing("tombstoned"));
        }
        Ok(())
    }

    /// Records that `listing` was accepted: raises the high-water mark.
    pub fn accept(&mut self, listing: &SignedListing) {
        let issued = listing.token().grant.issued_at;
        if self
            .high_water
            .as_ref()
            .is_none_or(|(mark, _)| issued > *mark)
        {
            self.high_water = Some((issued, listing.params().identity.clone()));
        }
    }

    /// Records a (verified) withdrawal of this name: its identity's
    /// tombstone becomes at least the withdrawal's `seq`. The high-water
    /// mark is kept.
    pub fn tombstone(&mut self, withdrawal: &Withdrawal) {
        match self
            .tombstones
            .iter_mut()
            .find(|(id, _)| *id == withdrawal.identity)
        {
            Some((_, seq)) => *seq = (*seq).max(withdrawal.seq),
            None => self
                .tombstones
                .push((withdrawal.identity.clone(), withdrawal.seq)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::listing::testing::{DIRECTORY, T0, card_for, grant};
    use crate::listing::{DirectoryKey, TokenGrant};
    use crate::rng::Rng;

    struct World {
        dk: DirectoryKey,
        rng: Rng,
    }

    impl World {
        fn listing(&self, ik: &Identity, seq: u64, issued_at: u64) -> SignedListing {
            let token = self
                .dk
                .issue_token(
                    &self.rng,
                    &TokenGrant {
                        issued_at,
                        expires_at: issued_at + 60 * 24 * 3600,
                        ..grant(&ik.id())
                    },
                )
                .unwrap();
            let mut c = card_for(ik, token, None);
            c.params.seq = seq;
            c.sign(ik).unwrap()
        }
    }

    /// Review N1: rotate A to B, B withdraws, and A's old (unexpired,
    /// unrevoked) token must not bring A back.
    #[test]
    fn a_superseded_key_cannot_take_the_name_back() {
        let w = World {
            dk: DirectoryKey::generate(&Rng::for_test("name-dk")).unwrap(),
            rng: Rng::for_test("name-tokens"),
        };
        let a = Identity::generate(&Rng::for_test("name-a")).unwrap();
        let b = Identity::generate(&Rng::for_test("name-b")).unwrap();
        let mut record = NameRecord::default();
        let a1 = w.listing(&a, 7, T0);
        record.admits(&a1, None).unwrap();
        record.accept(&a1);
        // Rotation: B under a later token.
        let b1 = w.listing(&b, 1, T0 + 3600);
        record.admits(&b1, Some(&a1)).unwrap();
        record.accept(&b1);
        assert_eq!(record.high_water, Some((T0 + 3600, b.id())));
        // B withdraws; nothing is stored any more.
        let wd = Withdrawal::sign(&b, DIRECTORY, "release-planner", 1, T0 + 7200).unwrap();
        record.tombstone(&wd);
        // A republishes under its old token, at any seq: refused.
        for seq in [8, crate::encoding::MAX_SAFE_INTEGER] {
            let again = w.listing(&a, seq, T0);
            let e = record.admits(&again, None).unwrap_err();
            assert_eq!(
                e,
                Error::InvalidListing("token older than the name's newest")
            );
            assert_eq!(e.kind(), crate::ErrorKind::Superseded);
        }
        // B can't republish what it withdrew, but can publish newer.
        let b_old = w.listing(&b, 1, T0 + 3600);
        assert_eq!(
            record.admits(&b_old, None),
            Err(Error::InvalidListing("tombstoned"))
        );
        let b2 = w.listing(&b, 2, T0 + 3600);
        record.admits(&b2, None).unwrap();
        // A token issued to A after B's (an operator decision) wins again.
        let a_renewed = w.listing(&a, 1, T0 + 9000);
        record.admits(&a_renewed, None).unwrap();
        // With a stored listing, the replacement rule applies too.
        let b_lower = w.listing(&b, 1, T0 + 3600);
        let mut r2 = NameRecord::default();
        r2.accept(&b2);
        assert_eq!(
            r2.admits(&b_lower, Some(&b2)),
            Err(Error::InvalidListing("does not replace the stored listing"))
        );
        // A tombstone of another identity never blocks.
        let mut r3 = NameRecord::default();
        r3.tombstone(&wd);
        r3.tombstone(&Withdrawal::sign(&b, DIRECTORY, "release-planner", 5, T0).unwrap());
        assert_eq!(r3.tombstones, vec![(b.id(), 5)]);
        r3.admits(&w.listing(&a, 1, T0), None).unwrap();
        // Ties at the mark go to the identity that set it.
        let mut r4 = NameRecord::default();
        r4.accept(&a1);
        r4.admits(&w.listing(&a, 8, T0), None).unwrap();
        assert_eq!(
            r4.admits(&w.listing(&b, 1, T0), None),
            Err(Error::InvalidListing("token older than the name's newest"))
        );
        // `accept` never lowers the mark, and a tie keeps its holder.
        r4.accept(&w.listing(&a, 9, T0 - 60));
        assert_eq!(r4.high_water, Some((T0, a.id())));
        r4.accept(&w.listing(&b, 1, T0));
        assert_eq!(r4.high_water, Some((T0, a.id())));
    }
}
