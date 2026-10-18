//! Fuzz target: the listing card parser and the other discovery parsers.
#![no_main]

use agentconnect_core::knock::Knock;
use agentconnect_core::listing::{
    ListingCard, ListingToken, OwnerFile, SignedListing, TokenRevocation, Withdrawal,
};
use libfuzzer_sys::fuzz_target;

// Listings, tokens, withdrawals and owner files come from the network, and
// knock plaintexts from anyone who can seal to a door. No parser may panic.
// An accepted listing is exactly its canonical bytes and re-parses to
// itself; an accepted unsigned card re-encodes to a form that parses back.
fuzz_target!(|data: &[u8]| {
    if let Ok(listing) = SignedListing::from_bytes(data) {
        assert_eq!(listing.bytes(), data);
        let again = SignedListing::from_bytes(listing.bytes()).unwrap();
        assert_eq!(again, listing);
    }
    if let Ok(card) = ListingCard::from_unsigned_json(data) {
        let unsigned = card.to_unsigned_json().unwrap();
        assert_eq!(ListingCard::from_unsigned_json(&unsigned).unwrap(), card);
    }
    if let Ok(token) = ListingToken::from_json(data) {
        assert_eq!(token.to_json().unwrap(), data);
    }
    if let Ok(rev) = TokenRevocation::from_json(data) {
        assert_eq!(rev.to_json().unwrap(), data);
    }
    if let Ok(w) = Withdrawal::from_json(data) {
        assert_eq!(w.to_json().unwrap(), data);
    }
    let _ = OwnerFile::parse(data);
    if let Ok(knock) = Knock::from_json(data) {
        assert_eq!(knock.to_json().as_slice(), data);
    }
});
