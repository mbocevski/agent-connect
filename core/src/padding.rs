//! Application message padding buckets (SPEC §7.1).
//!
//! OpenMLS pads a `PrivateMessage` so that its AEAD ciphertext is a multiple
//! of the configured padding size. Before each application message `core`
//! sets the padding size to the bucket that fits the message, so the
//! `PrivateMessage.ciphertext` field is **exactly** one bucket long. The rest
//! of the serialised message (group id, epoch, encrypted sender data, length
//! prefixes) is the same size for every application message in a group.

/// Bucket sizes in bytes: 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB.
pub const BUCKETS: [usize; 7] = [
    256,
    1 << 10,
    4 << 10,
    16 << 10,
    64 << 10,
    256 << 10,
    1 << 20,
];

/// Ed25519 signature with its two-byte length prefix (64 needs the 2-byte varint).
const SIGNATURE_FIELD: usize = 2 + 64;
/// AES-128-GCM tag.
const AEAD_TAG: usize = 16;

/// Length of the MLS variable-length integer prefix for `len` (RFC 9420 §2.1.2).
fn varint_len(len: usize) -> usize {
    match len {
        0..64 => 1,
        64..16_384 => 2,
        _ => 4,
    }
}

/// The AEAD ciphertext length of an application message carrying
/// `plaintext_len` bytes before padding: `application_data<V>`, the
/// signature, and the tag.
#[must_use]
pub fn unpadded_ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len + varint_len(plaintext_len) + SIGNATURE_FIELD + AEAD_TAG
}

/// The bucket an application message of `plaintext_len` bytes is padded to,
/// or `None` if it doesn't fit the largest bucket.
#[must_use]
pub fn bucket_for(plaintext_len: usize) -> Option<usize> {
    let needed = unpadded_ciphertext_len(plaintext_len);
    BUCKETS.into_iter().find(|&b| b >= needed)
}

/// The largest plaintext that fits the largest bucket.
#[must_use]
pub fn max_plaintext_len() -> usize {
    BUCKETS[BUCKETS.len() - 1] - 4 - SIGNATURE_FIELD - AEAD_TAG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_boundaries() {
        // 256 - 66 - 16 = 174, minus the 2-byte varint for lengths >= 64.
        assert_eq!(bucket_for(0), Some(256));
        assert_eq!(bucket_for(172), Some(256));
        assert_eq!(bucket_for(173), Some(1024));
        assert_eq!(bucket_for(max_plaintext_len()), Some(1 << 20));
        assert_eq!(bucket_for(max_plaintext_len() + 1), None);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 4);
    }
}
