//! Dynamic resharing of FROST signing keys.
//!
//! Implements [Wang's Verifiable Secret Resharing (VSR) Scheme
#![doc = "](https://www.semanticscholar.org/paper/Verifiable-Secret-Redistribution\
-for-Threshold-Wong-Wang/48d248779002b0015bdb99841a43395b526d5f8e)."]
//! FROST signing shares can be periodically rotated among signers to
//! protect against mobile and active adversaries. This allows old shares
//! to be 'revoked' (although only in a soft manner) and replaced with new shares.
//!
//! As a byproduct, resharing allows signers to change parameters of their
//! signing group, including setting a new threshold, changing identifiers,
//! adding new signers or excluding old signers from the new group of shares.
//! Resharing can be done even if some signers are offline; as long as the
//! signing threshold is met, the joint secret can be redistributed with new
//! shares and potentially a new threshold.
//!
//! Shares issued from before and after the resharing are mutually incompatible,
//! so it is imperative that at least the one threshold-subset of signers ACK
//! the resharing as successful before anyone deletes their old shares. See
//! [`reshare_step_2`] for more info.
//!
//! After a resharing occurs, the old shares are still usable. Normally, signers
//! are advised to delete their old shares, but nothing prevents them from keeping
//! the outdated shares either by maliciousness or through honest mistake.
//!
//! Downstream consumers should consider how inactive signers will be notified
//! about a resharing which occurrs while they are offline.

use std::collections::BTreeMap;

use crate::Error;
use crate::{frost, CryptoRng, Identifier, RngCore};

use super::{KeyPackage, PublicKeyPackage, SecretShare, SigningShare};

/// A subshare of a secret share. This contains the same data
/// as a [`SecretShare`], except it is actually a share of a share,
/// used in the process of resharing.
pub type SecretSubshare = SecretShare;

/// Split a secret signing share into a set of secret subshares (shares of a share).
///
/// `share_i` is our FROST signing share, which will be split into subshares.
///
/// `new_threshold` is the desired new minimum signer threshold after resharing.
/// All signers participating in resharing must specify the same `new_threshold`.
///
/// `new_idents` is a list of identifiers for peers to whom the secret subshares
/// will be distributed. Depending on use-case, these identifiers may be completely
/// new, or they may be the same as the old signing group from before resharing.
///
/// The resulting output maps peers' identifiers to the subshare which they should
/// receive. The commitment in each subshare is the same, and should be broadcast
/// to all subshare recipients. The secret subshare itself should be sent via
/// a private authenticated channel to the specific recipient which maps to it.
pub fn reshare_step_1<R: RngCore + CryptoRng>(
    share_i: &SigningShare,
    rng: &mut R,
    new_threshold: u16,
    new_idents: &[Identifier],
) -> Result<BTreeMap<Identifier, SecretSubshare>, Error> {
    frost::keys::resharing::reshare_step_1(share_i, rng, new_threshold, new_idents)
}

/// Verify and combine a set of secret subshares into a new FROST signing share.
///
/// `our_ident` is the identifier for ourself.
///
/// `old_pubkeys` is the old public key package for the group's joint FROST key.
///
/// `new_threshold` is the desired new minimum signer threshold after resharing.
/// All signers participating in resharing must specify the same `new_threshold`.
///
/// `new_idents` is the list of identifiers for peers to whom the secret subshares
/// are being distributed. Depending on use-case, these identifiers may be completely
/// new, or they may be the same as the old signing group from before resharing.
///
/// `received_subshares` maps identifiers to the secret subshare sent by those peers.
/// We assume the commitment in each subshare is consistent with a commitment publicly
/// broadcasted by the sender, i.e. we assume each peer has not equivocated by sending
/// inconsistent commitments to different subshare recipients.
///
/// The output is a new FROST secret signing share and public key package. The joint
/// public key will match the old joint public key, but the signing and verification
/// shares will be changed and will no longer be compatible with old shares from
/// before the resharing occurred.
///
/// The caller MUST ensure at least `new_threshold` signers ACK the resharing as successful.
/// We recommend having each signer broadcast their public verification shares to confirm
/// the new set of shares are all consistent. Only then can the previous shares be safely
/// overwritten.
pub fn reshare_step_2(
    our_ident: Identifier,
    old_pubkeys: &PublicKeyPackage,
    new_threshold: u16,
    new_idents: &[Identifier],
    received_subshares: &BTreeMap<Identifier, SecretSubshare>,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    frost::keys::resharing::reshare_step_2(
        our_ident,
        old_pubkeys,
        new_threshold,
        new_idents,
        received_subshares,
    )
}
