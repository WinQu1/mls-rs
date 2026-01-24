// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! Application-level messages used by Quarantined-TreeKEM (QTreeKEM).
//!
//! The QTreeKEM protocol introduces auxiliary messages for share recovery.
//! Rather than extending the MLS framing layer, these messages are encoded
//! into MLS `ApplicationData` payloads (i.e., sent as MLS application
//! messages over the existing PrivateMessage mechanism).

use alloc::vec::Vec;

use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::error::IntoAnyError;

use crate::{client::MlsError, tree_kem::node::LeafIndex};

/// Wire tags for quarantine application messages.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QuarantineAppMessageType {
    QuarantineEnd = 1,
    ShareRecovery = 2,
    ShareResend = 3,
}

/// Application message payloads for QTreeKEM share recovery.
#[derive(Clone, Debug, Eq, PartialEq, MlsEncode, MlsDecode, MlsSize)]
#[repr(u8)]
pub enum QuarantineAppMessage {
    /// Sent by a member that has ended quarantine (i.e., became active again).
    /// Receivers may discard cached shares for the specified (ghost_leaf, key_epoch).
    QuarantineEnd(QuarantineEnd) = 1,

    /// Sent by a re-activated member to request shares for a given (ghost_leaf, key_epoch).
    ShareRecovery(ShareRecovery) = 2,

    /// Sent by a shareholder in response to ShareRecovery.
    /// Since MLS application messages are broadcast, `target_rank` tells receivers
    /// who should accept the contained share(s).
    ShareResend(ShareResend) = 3,
}

#[derive(Clone, Debug, Eq, PartialEq, MlsEncode, MlsDecode, MlsSize)]
pub struct QuarantineEnd {
    pub ghost_leaf: LeafIndex,
    pub key_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, MlsEncode, MlsDecode, MlsSize)]
pub struct ShareRecovery {
    pub ghost_leaf: LeafIndex,
    pub key_epoch: u64,
    /// Leaf index of the requester at the time of request.
    pub requester_rank: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, MlsEncode, MlsDecode, MlsSize)]
pub struct ShareResend {
    pub ghost_leaf: LeafIndex,
    pub key_epoch: u64,
    pub target_rank: u32,
    /// The sender may include one or more shares it holds.
    pub shares: Vec<crate::tree_kem::GhostShareHolder>,
}

impl QuarantineAppMessage {
    pub fn encode_to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.mls_encode_to_vec()
            .map_err(|e| MlsError::SerializationError(e.into_any_error()))
    }

    pub fn decode_from_bytes(data: &[u8]) -> Result<Self, MlsError> {
        let mut r = data;
        Self::mls_decode(&mut r).map_err(|e| MlsError::SerializationError(e.into_any_error()))
    }
}
