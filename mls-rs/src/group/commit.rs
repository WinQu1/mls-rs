// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::{crypto::SignatureSecretKey, error::IntoAnyError};

use crate::{
    cipher_suite::CipherSuite,
    client::MlsError,
    client_config::ClientConfig,
    extension::RatchetTreeExt,
    identity::SigningIdentity,
    protocol_version::ProtocolVersion,
    signer::Signable,
    time::MlsTime,
    tree_kem::{kem::TreeKem, path_secret::PathSecret, TreeKemPrivate, UpdatePath},
    ExtensionList, MlsRules,
};

#[cfg(all(not(mls_build_async), feature = "rayon"))]
use {crate::iter::ParallelIteratorExt, rayon::prelude::*};

use crate::tree_kem::leaf_node::LeafNode;

#[cfg(not(feature = "private_message"))]
use crate::WireFormat;

#[cfg(feature = "psk")]
use crate::{
    group::{JustPreSharedKeyID, PskGroupId, ResumptionPSKUsage, ResumptionPsk},
    psk::ExternalPskId,
};

use super::{
    confirmation_tag::ConfirmationTag,
    framing::{Content, MlsMessage, MlsMessagePayload, Sender},
    key_schedule::{KeySchedule, WelcomeSecret},
    message_hash::MessageHash,
    message_processor::{path_update_required, MessageProcessor},
    message_signature::AuthenticatedContent,
    mls_rules::CommitDirection,
    proposal::{Proposal, ProposalOrRef},
    CommitEffect, CommitMessageDescription, EncryptedGroupSecrets, EpochSecrets, ExportedTree,
    Group, GroupContext, GroupInfo, GroupState, InterimTranscriptHash, NewEpoch,
    PendingCommitSnapshot, Welcome,
};

#[cfg(not(feature = "by_ref_proposal"))]
use super::proposal_cache::prepare_commit;

#[cfg(feature = "custom_proposal")]
use super::proposal::CustomProposal;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(mls_rs_core::arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct GhostLeafUpdate {
    pub leaf_index: crate::tree_kem::node::LeafIndex,
    pub leaf_node: LeafNode,
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(mls_rs_core::arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,

    /// QTreeKEM: deterministic mutations of other members' leaf nodes (ghost/quarantine
    /// maintenance). These changes are authenticated by the committer and must be applied
    /// deterministically by all receivers before validating the UpdatePath / tree hash.
    pub ghost_updates: Vec<GhostLeafUpdate>,
}

#[derive(Clone, PartialEq, Debug, MlsEncode, MlsDecode, MlsSize)]
pub(crate) struct PendingCommit {
    pub(crate) state: GroupState,
    pub(crate) epoch_secrets: EpochSecrets,
    pub(crate) private_tree: TreeKemPrivate,
    pub(crate) key_schedule: KeySchedule,
    pub(crate) signer: SignatureSecretKey,

    pub(crate) output: CommitMessageDescription,

    pub(crate) commit_message_hash: MessageHash,
}

#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone)]
pub struct CommitSecrets(pub(crate) PendingCommitSnapshot);

impl CommitSecrets {
    /// Deserialize the commit secrets from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        Ok(MlsDecode::mls_decode(&mut &*bytes).map(Self)?)
    }

    /// Serialize the commit secrets to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.0.mls_encode_to_vec()?)
    }
}

#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, Debug)]
#[non_exhaustive]
/// Result of MLS commit operation using
/// [`Group::commit`](crate::group::Group::commit) or
/// [`CommitBuilder::build`](CommitBuilder::build).
pub struct CommitOutput {
    /// Commit message to send to other group members.
    pub commit_message: MlsMessage,
    /// Welcome messages to send to new group members. If the commit does not add members,
    /// this list is empty. Otherwise, if [`MlsRules::commit_options`] returns `single_welcome_message`
    /// set to true, then this list contains a single message sent to all members. Else, the list
    /// contains one message for each added member. Recipients of each message can be identified using
    /// [`MlsMessage::key_package_reference`] of their key packages and
    /// [`MlsMessage::welcome_key_package_references`].
    pub welcome_messages: Vec<MlsMessage>,
    /// Ratchet tree that can be sent out of band if
    /// `ratchet_tree_extension` is not used according to
    /// [`MlsRules::commit_options`].
    pub ratchet_tree: Option<ExportedTree<'static>>,
    /// A group info that can be provided to new members in order to enable external commit
    /// functionality. This value is set if [`MlsRules::commit_options`] returns
    /// `allow_external_commit` set to true.
    pub external_commit_group_info: Option<MlsMessage>,
    /// Proposals that were received in the prior epoch but not included in the following commit.
    #[cfg(feature = "by_ref_proposal")]
    pub unused_proposals: Vec<crate::mls_rules::ProposalInfo<Proposal>>,
    /// Indicator that the commit contains a path update
    pub contains_update_path: bool,
}

#[cfg_attr(all(feature = "ffi", not(test)), ::safer_ffi_gen::safer_ffi_gen)]
impl CommitOutput {
    /// Commit message to send to other group members.
    #[cfg(feature = "ffi")]
    pub fn commit_message(&self) -> &MlsMessage {
        &self.commit_message
    }

    /// Welcome message to send to new group members.
    #[cfg(feature = "ffi")]
    pub fn welcome_messages(&self) -> &[MlsMessage] {
        &self.welcome_messages
    }

    /// Ratchet tree that can be sent out of band if
    /// `ratchet_tree_extension` is not used according to
    /// [`MlsRules::commit_options`].
    #[cfg(feature = "ffi")]
    pub fn ratchet_tree(&self) -> Option<&ExportedTree<'static>> {
        self.ratchet_tree.as_ref()
    }

    /// A group info that can be provided to new members in order to enable external commit
    /// functionality. This value is set if [`MlsRules::commit_options`] returns
    /// `allow_external_commit` set to true.
    #[cfg(feature = "ffi")]
    pub fn external_commit_group_info(&self) -> Option<&MlsMessage> {
        self.external_commit_group_info.as_ref()
    }

    /// Proposals that were received in the prior epoch but not included in the following commit.
    #[cfg(all(feature = "ffi", feature = "by_ref_proposal"))]
    pub fn unused_proposals(&self) -> &[crate::mls_rules::ProposalInfo<Proposal>] {
        &self.unused_proposals
    }
}

/// Build a commit with multiple proposals by-value.
///
/// Proposals within a commit can be by-value or by-reference.
/// Proposals received during the current epoch will be added to the resulting
/// commit by-reference automatically so long as they pass the rules defined
/// in the current
/// [proposal rules](crate::client_builder::ClientBuilder::mls_rules).
pub struct CommitBuilder<'a, C>
where
    C: ClientConfig + Clone,
{
    group: &'a mut Group<C>,
    pub(super) proposals: Vec<Proposal>,
    authenticated_data: Vec<u8>,
    group_info_extensions: ExtensionList,
    new_signer: Option<SignatureSecretKey>,
    new_signing_identity: Option<SigningIdentity>,
    new_leaf_node_extensions: Option<ExtensionList>,
    commit_time: Option<MlsTime>,
}

impl<'a, C> CommitBuilder<'a, C>
where
    C: ClientConfig + Clone,
{
    /// Insert an [`AddProposal`](crate::group::proposal::AddProposal) into
    /// the current commit that is being built.
    pub fn add_member(mut self, key_package: MlsMessage) -> Result<CommitBuilder<'a, C>, MlsError> {
        let proposal = self.group.add_proposal(key_package)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Set group info extensions that will be inserted into the resulting
    /// [welcome messages](CommitOutput::welcome_messages) for new members.
    ///
    /// Group info extensions that are transmitted as part of a welcome message
    /// are encrypted along with other private values.
    ///
    /// These extensions can be retrieved as part of
    /// [`NewMemberInfo`](crate::group::NewMemberInfo) that is returned
    /// by joining the group via
    /// [`Client::join_group`](crate::Client::join_group).
    pub fn set_group_info_ext(self, extensions: ExtensionList) -> Self {
        Self {
            group_info_extensions: extensions,
            ..self
        }
    }

    /// Insert a [`RemoveProposal`](crate::group::proposal::RemoveProposal) into
    /// the current commit that is being built.
    pub fn remove_member(mut self, index: u32) -> Result<Self, MlsError> {
        let proposal = self.group.remove_proposal(index)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a
    /// [`GroupContextExtensions`](crate::group::proposal::Proposal::GroupContextExtensions)
    /// into the current commit that is being built.
    pub fn set_group_context_ext(mut self, extensions: ExtensionList) -> Result<Self, MlsError> {
        let proposal = self.group.group_context_extensions_proposal(extensions);
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a
    /// [`PreSharedKeyProposal`](crate::group::proposal::PreSharedKeyProposal) with
    /// an external PSK into the current commit that is being built.
    #[cfg(feature = "psk")]
    pub fn add_external_psk(mut self, psk_id: ExternalPskId) -> Result<Self, MlsError> {
        let key_id = JustPreSharedKeyID::External(psk_id);
        let proposal = self.group.psk_proposal(key_id)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a
    /// [`PreSharedKeyProposal`](crate::group::proposal::PreSharedKeyProposal) with
    /// a resumption PSK into the current commit that is being built.
    #[cfg(feature = "psk")]
    pub fn add_resumption_psk(mut self, psk_epoch: u64) -> Result<Self, MlsError> {
        let psk_id = ResumptionPsk {
            psk_epoch,
            usage: ResumptionPSKUsage::Application,
            psk_group_id: PskGroupId(self.group.group_id().to_vec()),
        };

        let key_id = JustPreSharedKeyID::Resumption(psk_id);
        let proposal = self.group.psk_proposal(key_id)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a [`ReInitProposal`](crate::group::proposal::ReInitProposal) into
    /// the current commit that is being built.
    pub fn reinit(
        mut self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Self, MlsError> {
        let proposal = self
            .group
            .reinit_proposal(group_id, version, cipher_suite, extensions)?;

        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a [`CustomProposal`](crate::group::proposal::CustomProposal) into
    /// the current commit that is being built.
    #[cfg(feature = "custom_proposal")]
    pub fn custom_proposal(mut self, proposal: CustomProposal) -> Self {
        self.proposals.push(Proposal::Custom(proposal));
        self
    }

    /// Insert a proposal that was previously constructed such as when a
    /// proposal is returned from
    /// [`NewEpoch::unused_proposals`](super::NewEpoch::unused_proposals).
    pub fn raw_proposal(mut self, proposal: Proposal) -> Self {
        self.proposals.push(proposal);
        self
    }

    /// Insert proposals that were previously constructed such as when a
    /// proposal is returned from
    /// [`NewEpoch::unused_proposals`](super::NewEpoch::unused_proposals).
    pub fn raw_proposals(mut self, mut proposals: Vec<Proposal>) -> Self {
        self.proposals.append(&mut proposals);
        self
    }

    /// Add additional authenticated data to the commit.
    ///
    /// # Warning
    ///
    /// The data provided here is always sent unencrypted.
    pub fn authenticated_data(self, authenticated_data: Vec<u8>) -> Self {
        Self {
            authenticated_data,
            ..self
        }
    }

    /// Change the committer's signing identity as part of making this commit.
    /// This will only succeed if the [`IdentityProvider`](crate::IdentityProvider)
    /// in use by the group considers the credential inside this signing_identity
    /// [valid](crate::IdentityProvider::validate_member)
    /// and results in the same
    /// [identity](crate::IdentityProvider::identity)
    /// being used.
    pub fn set_new_signing_identity(
        self,
        signer: SignatureSecretKey,
        signing_identity: SigningIdentity,
    ) -> Self {
        Self {
            new_signer: Some(signer),
            new_signing_identity: Some(signing_identity),
            ..self
        }
    }

    /// Change the committer's leaf node extensions as part of making this commit.
    pub fn set_leaf_node_extensions(self, new_leaf_node_extensions: ExtensionList) -> Self {
        Self {
            new_leaf_node_extensions: Some(new_leaf_node_extensions),
            ..self
        }
    }

    /// Add a time to associate with the commit creation.
    pub fn commit_time(self, commit_time: MlsTime) -> Self {
        Self {
            commit_time: Some(commit_time),
            ..self
        }
    }

    /// Finalize the commit to send.
    ///
    /// # Errors
    ///
    /// This function will return an error if any of the proposals provided
    /// are not contextually valid according to the rules defined by the
    /// MLS RFC, or if they do not pass the custom rules defined by the current
    /// [proposal rules](crate::client_builder::ClientBuilder::mls_rules).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build(self) -> Result<CommitOutput, MlsError> {
        let (output, pending_commit) = self
            .group
            .commit_internal(
                self.proposals,
                None,
                self.authenticated_data,
                self.group_info_extensions,
                self.new_signer,
                self.new_signing_identity,
                self.new_leaf_node_extensions,
                self.commit_time,
            )
            .await?;

        self.group.pending_commit = pending_commit.try_into()?;

        Ok(output)
    }

    /// The same function as `GroupBuilder::build` except the secrets generated
    /// for the commit are outputted instead of being cached internally.
    ///
    /// A detached commit can be applied using `Group::apply_detached_commit`.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build_detached(self) -> Result<(CommitOutput, CommitSecrets), MlsError> {
        let (output, pending_commit) = self
            .group
            .commit_internal(
                self.proposals,
                None,
                self.authenticated_data,
                self.group_info_extensions,
                self.new_signer,
                self.new_signing_identity,
                self.new_leaf_node_extensions,
                self.commit_time,
            )
            .await?;

        Ok((
            output,
            CommitSecrets(PendingCommitSnapshot::PendingCommit(
                pending_commit.mls_encode_to_vec()?,
            )),
        ))
    }
}

use crate::tree_kem::node::LeafIndex;

#[derive(Debug, Clone)]
pub(crate) enum GhostKeyReason {
    NewQuarantine,
    Rotation,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingGhostKeyDerivation {
    pub(crate) leaf_index: LeafIndex,
    pub(crate) epoch: u64,        // next_epoch
    pub(crate) seed: Vec<u8>,     // s_g
    pub(crate) reason: GhostKeyReason,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    /// Perform a commit of received proposals.
    ///
    /// This function is the equivalent of [`Group::commit_builder`] immediately
    /// followed by [`CommitBuilder::build`]. Any received proposals since the
    /// last commit will be included in the resulting message by-reference.
    ///
    /// Data provided in the `authenticated_data` field will be placed into
    /// the resulting commit message unencrypted.
    ///
    /// # Pending Commits
    ///
    /// When a commit is created, it is not applied immediately in order to
    /// allow for the resolution of conflicts when multiple members of a group
    /// attempt to make commits at the same time. For example, a central relay
    /// can be used to decide which commit should be accepted by the group by
    /// determining a consistent view of commit packet order for all clients.
    ///
    /// Pending commits are stored internally as part of the group's state
    /// so they do not need to be tracked outside of this library. Any commit
    /// message that is processed before calling [Group::apply_pending_commit]
    /// will clear the currently pending commit.
    ///
    /// # Empty Commits
    ///
    /// Sending a commit that contains no proposals is a valid operation
    /// within the MLS protocol. It is useful for providing stronger forward
    /// secrecy and post-compromise security, especially for long running
    /// groups when group membership does not change often.
    ///
    /// # Path Updates
    ///
    /// Path updates provide forward secrecy and post-compromise security
    /// within the MLS protocol.
    /// The `path_required` option returned by [`MlsRules::commit_options`](`crate::MlsRules::commit_options`)
    /// controls the ability of a group to send a commit without a path update.
    /// An update path will automatically be sent if there are no proposals
    /// in the commit, or if any proposal other than
    /// [`Add`](crate::group::proposal::Proposal::Add),
    /// [`Psk`](crate::group::proposal::Proposal::Psk),
    /// or [`ReInit`](crate::group::proposal::Proposal::ReInit) are part of the commit.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn commit(&mut self, authenticated_data: Vec<u8>) -> Result<CommitOutput, MlsError> {
        self.commit_builder()
            .authenticated_data(authenticated_data)
            .build()
            .await
    }

    /// The same function as `Group::commit` except the secrets generated
    /// for the commit are outputted instead of being cached internally.
    ///
    /// A detached commit can be applied using `Group::apply_detached_commit`.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn commit_detached(
        &mut self,
        authenticated_data: Vec<u8>,
    ) -> Result<(CommitOutput, CommitSecrets), MlsError> {
        self.commit_builder()
            .authenticated_data(authenticated_data)
            .build_detached()
            .await
    }

    /// Create a new commit builder that can include proposals
    /// by-value.
    pub fn commit_builder(&mut self) -> CommitBuilder<'_, C> {
        CommitBuilder {
            group: self,
            proposals: Default::default(),
            authenticated_data: Default::default(),
            group_info_extensions: Default::default(),
            new_signer: Default::default(),
            new_signing_identity: Default::default(),
            new_leaf_node_extensions: Default::default(),
            commit_time: None,
        }
    }

    /// Returns commit and optional [`MlsMessage`] containing a welcome message
    /// for newly added members.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn commit_internal(
        &mut self,
        proposals: Vec<Proposal>,
        external_leaf: Option<&LeafNode>,
        authenticated_data: Vec<u8>,
        mut welcome_group_info_extensions: ExtensionList,
        new_signer: Option<SignatureSecretKey>,
        new_signing_identity: Option<SigningIdentity>,
        new_leaf_node_extensions: Option<ExtensionList>,
        commit_time: Option<MlsTime>,
    ) -> Result<(CommitOutput, PendingCommit), MlsError> {
        if !self.pending_commit.is_none() {
            return Err(MlsError::ExistingPendingCommit);
        }

        if self.state.pending_reinit.is_some() {
            return Err(MlsError::GroupUsedAfterReInit);
        }

        let mls_rules = self.config.mls_rules();

        let is_external = external_leaf.is_some();

        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let sender = if is_external {
            Sender::NewMemberCommit
        } else {
            Sender::Member(*self.private_tree.self_index)
        };

        let new_signer = new_signer.unwrap_or_else(|| self.signer.clone());
        let old_signer = &self.signer;

        #[cfg(feature = "std")]
        let time = Some(crate::time::MlsTime::now());

        #[cfg(not(feature = "std"))]
        let time = None;

        let time = if commit_time.is_some() {
            commit_time
        } else {
            time
        };
        let mut proposals = proposals;
        let next_epoch = self.state.context.epoch + 1;
        let mut pending_ghost_keys = Vec::<PendingGhostKeyDerivation>::new();
        let ghost_updates = self
            .update_ghost_members(&mut proposals, &mut pending_ghost_keys, next_epoch)
            .await?;

        #[cfg(feature = "by_ref_proposal")]
        let proposals = self.state.proposals.prepare_commit(sender, proposals);

        #[cfg(not(feature = "by_ref_proposal"))]
        let proposals = prepare_commit(sender, proposals);

        let mut provisional_state = self
            .state
            .apply_resolved(
                sender,
                proposals,
                external_leaf,
                &self.config.identity_provider(),
                &self.cipher_suite_provider,
                &self.config.secret_store(),
                &mls_rules,
                time,
                CommitDirection::Send,
            )
            .await?;

        // QTreeKEM (Kotlin-style): apply ghost/quarantine tree mutations directly to the
        // provisional tree before validating update paths and computing tree hashes.
        if !ghost_updates.is_empty() {
            let mut updated_leaves = Vec::with_capacity(ghost_updates.len());

            for gu in ghost_updates.iter() {
                if let Ok(leaf) = provisional_state
                    .public_tree
                    .nodes
                    .borrow_as_leaf_mut(gu.leaf_index)
                {
                    *leaf = gu.leaf_node.clone();
                    updated_leaves.push(gu.leaf_index);
                }
            }

            if !updated_leaves.is_empty() {
                provisional_state
                    .public_tree
                    .update_hashes(&updated_leaves, &self.cipher_suite_provider)
                    .await?;

                provisional_state.group_context.tree_hash = provisional_state
                    .public_tree
                    .tree_hash(&self.cipher_suite_provider)
                    .await?;
            }
        }

        let (mut provisional_private_tree, _) =
            self.provisional_private_tree(&provisional_state)?;

        if is_external {
            provisional_private_tree.self_index = provisional_state
                .external_init_index
                .ok_or(MlsError::ExternalCommitMissingExternalInit)?;

            self.private_tree.self_index = provisional_private_tree.self_index;
        }

        // Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        let commit_options = mls_rules
            .commit_options(
                &provisional_state.public_tree.roster(),
                &provisional_state.group_context,
                &provisional_state.applied_proposals,
            )
            .map_err(|e| MlsError::MlsRulesError(e.into_any_error()))?;

        let perform_path_update = commit_options.path_required
            || path_update_required(&provisional_state.applied_proposals)
            || !pending_ghost_keys.is_empty();

        let (update_path, path_secrets, commit_secret) = if perform_path_update {
            // If populating the path field: Create an UpdatePath using the new tree. Any new
            // member (from an add proposal) MUST be excluded from the resolution during the
            // computation of the UpdatePath. The GroupContext for this operation uses the
            // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
            // GroupContext object. The leaf_key_package for this UpdatePath must have a
            // parent_hash extension.

            let new_leaf_node_extensions =
                new_leaf_node_extensions.or(external_leaf.map(|ln| ln.ungreased_extensions()));

            let new_leaf_node_extensions = match new_leaf_node_extensions {
                Some(extensions) => extensions,
                // If we are not setting new extensions and this is not an external leaf then the current node MUST exist.
                None => self.current_user_leaf_node()?.ungreased_extensions(),
            };

            let self_index = provisional_private_tree.self_index;

            let path = provisional_state.public_tree.nodes.direct_copath(self_index);
            let filtered = provisional_state.public_tree.nodes.filtered(self_index)?;

            let mut positions: Vec<usize> = Vec::new();
            for (i, f) in filtered.iter().enumerate() {
                if !*f {
                    positions.push(i);
                }
            }

            let mut ghost_shares_per_path_pos: Vec<Vec<crate::tree_kem::GhostShare>> =
                vec![Vec::new(); path.len()];

            for pending in pending_ghost_keys.iter() {
                let params = self.config.ghost_sharing_params();
                let desired_t = params.threshold_t as usize;
                let desired_m = params.share_count_m as usize;

                if desired_t == 0 || desired_m == 0 || desired_m < desired_t {
                    continue;
                }
                if positions.len() + 1 < desired_t {
                    continue;
                }

                let m = core::cmp::min(desired_m, positions.len() + 1);
                if m == 0 {
                    continue;
                }
                let t = desired_t as u8;

                let shares = crate::group::secret_sharing::split_seed_bytes(&pending.seed, t, m as u8)
                    .map_err(|e| MlsError::SerializationError(e.into_any_error()))?;

                // Store the first share locally ("share 0").
                if let Some(first) = shares.first() {
                    provisional_private_tree.ghost_share_holders.push(crate::tree_kem::GhostShareHolder {
                        ghost_leaf: pending.leaf_index,
                        key_epoch: pending.epoch,
                        share_id: first.id,
                        holder_rank: *provisional_private_tree.self_index,
                        share_value: first.bytes.clone(),
                    });
                }
                let mut k: usize = 0;
                for s in shares.into_iter().skip(1) {
                    let pos = positions[k % positions.len()];
                    k += 1;

                    ghost_shares_per_path_pos[pos].push(crate::tree_kem::GhostShare {
                        ghost_leaf: pending.leaf_index,
                        key_epoch: pending.epoch,
                        share_id: s.id,
                        share_value: s.bytes,
                    });
                }
            }

            let encap_gen = TreeKem::new(
                &mut provisional_state.public_tree,
                &mut provisional_private_tree,
            )
            .encap(
                &mut provisional_state.group_context,
                &provisional_state.indexes_of_added_kpkgs,
                &new_signer,
                Some(self.config.leaf_properties(new_leaf_node_extensions)),
                new_signing_identity,
                &self.cipher_suite_provider,
                &ghost_shares_per_path_pos,
                #[cfg(test)]
                &self.commit_modifiers,
            )
            .await?;

            (
                Some(encap_gen.update_path),
                Some(encap_gen.path_secrets),
                encap_gen.commit_secret,
            )
        } else {
            // Update the tree hash, since it was not updated by encap.
            provisional_state
                .public_tree
                .update_hashes(
                    &[provisional_private_tree.self_index],
                    &self.cipher_suite_provider,
                )
                .await?;

            provisional_state.group_context.tree_hash = provisional_state
                .public_tree
                .tree_hash(&self.cipher_suite_provider)
                .await?;

            (None, None, PathSecret::empty(&self.cipher_suite_provider))
        };

        #[cfg(feature = "psk")]
        let (psk_secret, psks) = self
            .get_psk(&provisional_state.applied_proposals.psks)
            .await?;

        #[cfg(not(feature = "psk"))]
        let psk_secret = self.get_psk();

        let added_key_pkgs: Vec<_> = provisional_state
            .applied_proposals
            .additions
            .iter()
            .map(|info| info.proposal.key_package.clone())
            .collect();

        let commit = Commit {
            proposals: provisional_state.applied_proposals.proposals_or_refs(),
            path: update_path,
            ghost_updates,
        };

        let mut auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            self.context(),
            sender,
            Content::Commit(Box::new(commit)),
            old_signer,
            #[cfg(feature = "private_message")]
            self.encryption_options()?.control_wire_format(sender),
            #[cfg(not(feature = "private_message"))]
            WireFormat::PublicMessage,
            authenticated_data,
        )
        .await?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MlsPlaintext.
        let confirmed_transcript_hash = super::transcript_hash::create(
            self.cipher_suite_provider(),
            &self.state.interim_transcript_hash,
            &auth_content,
        )
        .await?;

        provisional_state.group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        let key_schedule_result = KeySchedule::from_key_schedule(
            &self.key_schedule,
            &commit_secret,
            &provisional_state.group_context,
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            provisional_state.public_tree.total_leaf_count(),
            &psk_secret,
            &self.cipher_suite_provider,
        )
        .await?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_state.group_context.confirmed_transcript_hash,
            &self.cipher_suite_provider,
        )
        .await?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            self.cipher_suite_provider(),
            &provisional_state.group_context.confirmed_transcript_hash,
            &confirmation_tag,
        )
        .await?;

        auth_content.auth.confirmation_tag = Some(confirmation_tag.clone());

        let ratchet_tree_ext = commit_options
            .ratchet_tree_extension
            .then(|| RatchetTreeExt {
                tree_data: ExportedTree::new(provisional_state.public_tree.nodes.clone()),
            });

        // Generate external commit group info if required by commit_options
        let external_commit_group_info = match commit_options.allow_external_commit {
            true => {
                let mut extensions = ExtensionList::new();

                extensions.set_from({
                    key_schedule_result
                        .key_schedule
                        .get_external_key_pair_ext(&self.cipher_suite_provider)
                        .await?
                })?;

                if let Some(ref ratchet_tree_ext) = ratchet_tree_ext {
                    if !commit_options.always_out_of_band_ratchet_tree {
                        extensions.set_from(ratchet_tree_ext.clone())?;
                    }
                }

                let info = self
                    .make_group_info(
                        &provisional_state.group_context,
                        extensions,
                        &confirmation_tag,
                        &new_signer,
                    )
                    .await?;

                let msg =
                    MlsMessage::new(self.protocol_version(), MlsMessagePayload::GroupInfo(info));

                Some(msg)
            }
            false => None,
        };

        // Build the group info that will be placed into the welcome messages.
        // Add the ratchet tree extension if necessary
        if let Some(ratchet_tree_ext) = ratchet_tree_ext {
            welcome_group_info_extensions.set_from(ratchet_tree_ext)?;
        }

        let welcome_group_info = self
            .make_group_info(
                &provisional_state.group_context,
                welcome_group_info_extensions,
                &confirmation_tag,
                &new_signer,
            )
            .await?;

        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret = WelcomeSecret::from_joiner_secret(
            &self.cipher_suite_provider,
            &key_schedule_result.joiner_secret,
            &psk_secret,
        )
        .await?;

        let encrypted_group_info = welcome_secret
            .encrypt(&welcome_group_info.mls_encode_to_vec()?)
            .await?;

        // Encrypt path secrets and joiner secret to new members
        let path_secrets = path_secrets.as_ref();

        #[cfg(not(any(mls_build_async, not(feature = "rayon"))))]
        let encrypted_path_secrets: Vec<_> = added_key_pkgs
            .into_par_iter()
            .zip(&provisional_state.indexes_of_added_kpkgs)
            .map(|(key_package, leaf_index)| {
                self.encrypt_group_secrets(
                    &key_package,
                    *leaf_index,
                    &key_schedule_result.joiner_secret,
                    path_secrets,
                    #[cfg(feature = "psk")]
                    psks.clone(),
                    &encrypted_group_info,
                )
            })
            .try_collect()?;

        #[cfg(any(mls_build_async, not(feature = "rayon")))]
        let encrypted_path_secrets = {
            let mut secrets = Vec::new();

            for (key_package, leaf_index) in added_key_pkgs
                .into_iter()
                .zip(&provisional_state.indexes_of_added_kpkgs)
            {
                secrets.push(
                    self.encrypt_group_secrets(
                        &key_package,
                        *leaf_index,
                        &key_schedule_result.joiner_secret,
                        path_secrets,
                        #[cfg(feature = "psk")]
                        psks.clone(),
                        &encrypted_group_info,
                    )
                    .await?,
                );
            }

            secrets
        };

        let welcome_messages =
            if commit_options.single_welcome_message && !encrypted_path_secrets.is_empty() {
                vec![self.make_welcome_message(encrypted_path_secrets, encrypted_group_info)]
            } else {
                encrypted_path_secrets
                    .into_iter()
                    .map(|s| self.make_welcome_message(vec![s], encrypted_group_info.clone()))
                    .collect()
            };

        let commit_message = self.format_for_wire(auth_content.clone()).await?;

        // TODO is it necessary to clone the tree here? or can we just output serialized bytes?
        let ratchet_tree = (!commit_options.ratchet_tree_extension
            || commit_options.always_out_of_band_ratchet_tree)
            .then(|| ExportedTree::new(provisional_state.public_tree.nodes.clone()));

        let pending_reinit = provisional_state
            .applied_proposals
            .reinitializations
            .first();

        let pending_commit = PendingCommit {
            output: CommitMessageDescription {
                is_external: matches!(auth_content.content.sender, Sender::NewMemberCommit),
                authenticated_data: auth_content.content.authenticated_data,
                committer: *provisional_private_tree.self_index,
                effect: match pending_reinit {
                    Some(r) => CommitEffect::ReInit(r.clone()),
                    None => CommitEffect::NewEpoch(
                        NewEpoch::new(self.state.clone(), &provisional_state).into(),
                    ),
                },
            },

            state: GroupState {
                #[cfg(feature = "by_ref_proposal")]
                proposals: crate::group::ProposalCache::new(
                    self.protocol_version(),
                    self.group_id().to_vec(),
                ),
                context: provisional_state.group_context,
                public_tree: provisional_state.public_tree,
                interim_transcript_hash,
                pending_reinit: pending_reinit.map(|r| r.proposal.clone()),
                confirmation_tag,
            },

            commit_message_hash: MessageHash::compute(&self.cipher_suite_provider, &commit_message)
                .await?,
            signer: new_signer,
            epoch_secrets: key_schedule_result.epoch_secrets,
            key_schedule: key_schedule_result.key_schedule,

            private_tree: provisional_private_tree,
        };

        let output = CommitOutput {
            commit_message,
            welcome_messages,
            ratchet_tree,
            external_commit_group_info,
            contains_update_path: perform_path_update,
            #[cfg(feature = "by_ref_proposal")]
            unused_proposals: provisional_state.unused_proposals,
        };

        Ok((output, pending_commit))
    }
    
    // Construct a GroupInfo reflecting the new state
    // Group ID, epoch, tree, and confirmed transcript hash from the new state
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_group_info(
        &self,
        group_context: &GroupContext,
        extensions: ExtensionList,
        confirmation_tag: &ConfirmationTag,
        signer: &SignatureSecretKey,
    ) -> Result<GroupInfo, MlsError> {
        let mut group_info = GroupInfo {
            group_context: group_context.clone(),
            extensions,
            confirmation_tag: confirmation_tag.clone(), // The confirmation_tag from the MlsPlaintext object
            signer: self.current_member_leaf_index(),
            signature: vec![],
        };

        group_info.grease(self.cipher_suite_provider())?;

        // Sign the GroupInfo using the member's private signing key
        group_info
            .sign(&self.cipher_suite_provider, signer, &())
            .await?;

        Ok(group_info)
    }

    fn make_welcome_message(
        &self,
        secrets: Vec<EncryptedGroupSecrets>,
        encrypted_group_info: Vec<u8>,
    ) -> MlsMessage {
        MlsMessage::new(
            self.context().protocol_version,
            MlsMessagePayload::Welcome(Welcome {
                cipher_suite: self.context().cipher_suite,
                secrets,
                encrypted_group_info,
            }),
        )
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn update_ghost_members(
        &self,
        proposals: &mut Vec<super::proposal::Proposal>,
        pending_ghost_keys: &mut Vec<PendingGhostKeyDerivation>,
        next_epoch: u64,
    ) -> Result<Vec<GhostLeafUpdate>, crate::client::MlsError> {
        use crate::group::proposal::{Proposal, RemoveProposal};
        use crate::crypto::CipherSuiteProvider;

        let inactivity_delay = GroupState::INACTIVITY_DELAY;
        let ghost_update_delay = GroupState::GHOST_KEY_UPDATE_DELAY;
        let delete_delay =    GroupState::DELETE_FROM_QUARANTINE_DELAY;

        let mut ghost_updates = Vec::<GhostLeafUpdate>::new();

        for (leaf_index, leaf) in self.state.public_tree.non_empty_leaves() {
            let is_ghost = leaf.equar != 0;

            if is_ghost && next_epoch.saturating_sub(leaf.equar) >= delete_delay {
                proposals.push(Proposal::Remove(RemoveProposal {
                    to_remove: leaf_index,
                }));
                continue;
            }

            if !is_ghost && next_epoch.saturating_sub(leaf.epk) >= inactivity_delay {
                let mut new_leaf = leaf.clone();
                let seed_len = self.cipher_suite_provider.kdf_extract_size();
                let seed = self
                    .cipher_suite_provider
                    .random_bytes_vec(seed_len)
                    .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;
                let (_sk, pk) = self
                    .cipher_suite_provider
                    .kem_derive(&seed)
                    .await
                    .map_err(|e| MlsError::CryptoProviderError(
                        e.into_any_error(),
                    ))?;
                pending_ghost_keys.push(PendingGhostKeyDerivation {
                    leaf_index,
                    epoch: next_epoch,
                    seed,
                    reason: GhostKeyReason::NewQuarantine,
                });
                new_leaf.public_key = pk;
                new_leaf.epk = next_epoch;
                new_leaf.mark_as_ghost(next_epoch);

                ghost_updates.push(GhostLeafUpdate {
                    leaf_index,
                    leaf_node: new_leaf,
                });
                continue;
            }

            if is_ghost && next_epoch.saturating_sub(leaf.epk) >= ghost_update_delay {
                let mut new_leaf = leaf.clone();
                let seed_len = self.cipher_suite_provider.kdf_extract_size();
                let seed = self
                    .cipher_suite_provider
                    .random_bytes_vec(seed_len)
                    .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;
            
                let (_sk, pk) = self
                    .cipher_suite_provider
                    .kem_derive(&seed)
                    .await
                    .map_err(|e| MlsError::CryptoProviderError(
                        e.into_any_error(),
                    ))?;
                pending_ghost_keys.push(PendingGhostKeyDerivation {
                    leaf_index,
                    epoch: next_epoch,
                    seed,
                    reason: GhostKeyReason::Rotation,
                });
                new_leaf.public_key = pk;
                new_leaf.epk = next_epoch;
                new_leaf.refresh_ghost_key(next_epoch);

                ghost_updates.push(GhostLeafUpdate {
                    leaf_index,
                    leaf_node: new_leaf,
                });
            }
        }

        Ok(ghost_updates)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::vec::Vec;

    use crate::{
        crypto::SignatureSecretKey,
        tree_kem::{leaf_node::LeafNode, TreeKemPublic, UpdatePathNode},
    };

    #[derive(Copy, Clone, Debug)]
    pub struct CommitModifiers {
        pub modify_leaf: fn(&mut LeafNode, &SignatureSecretKey) -> Option<SignatureSecretKey>,
        pub modify_tree: fn(&mut TreeKemPublic),
        pub modify_path: fn(Vec<UpdatePathNode>) -> Vec<UpdatePathNode>,
    }

    impl Default for CommitModifiers {
        fn default() -> Self {
            Self {
                modify_leaf: |_, _| None,
                modify_tree: |_| (),
                modify_path: |a| a,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::group::test_utils::get_test_25519_key;

    use super::*;

    // ---------------------------------------------------------------------
    // QTreeKEM – tests for implementation plan steps 1–4
    // ---------------------------------------------------------------------

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_mark_as_ghost() {
        use crate::client::test_utils::TEST_CIPHER_SUITE;
        use crate::identity::test_utils::get_test_signing_identity;
        use crate::tree_kem::leaf_node::{LeafNode, LeafNodeSource};

        // Create a minimal LeafNode instance (crypto material irrelevant for mark_as_ghost).
        let (sid, _ssk) = get_test_signing_identity(TEST_CIPHER_SUITE, b"member").await;

        let mut leaf = LeafNode {
            public_key: get_test_25519_key(0),
            signing_identity: Some(sid),
            capabilities: Default::default(),
            leaf_node_source: LeafNodeSource::Update,
            extensions: Default::default(),
            epk: 7,
            equar: 0,
            signature: vec![1, 2, 3],
        };

        let epoch = 42u64;
        leaf.mark_as_ghost(epoch);

        assert!(leaf.is_ghost());
        assert_eq!(leaf.equar, epoch);
        assert_eq!(leaf.epk, epoch);
        assert_eq!(leaf.leaf_node_source, LeafNodeSource::Ghost);
        assert!(leaf.signing_identity.is_none());
        assert_eq!(leaf.signature, vec![0u8]);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_commit() {
        use crate::client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION};
        use crate::group::test_utils::test_n_member_group;

        // Group (groups[0] = Alice and groups[1] = Bob)
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 2).await;
        
        // A starts commit without proposals
        let commit_output = groups[0].commit(vec![]).await.unwrap();
        let commit_msg = commit_output.commit_message;

        // Alice applies her own pending commit (this is required for the committer).
        groups[0].apply_pending_commit().await.unwrap();

        // B applies commit
        let res = groups[1].process_message(commit_msg).await;
        assert!(res.is_ok(), "Bob failed to apply commit: {:?}", res.err());
        assert_eq!(groups[0].context().epoch, groups[1].context().epoch);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_update_ghost_members() {
        use crate::client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION};
        use crate::group::state::GroupState;
        use crate::group::test_utils::test_n_member_group;
        use crate::tree_kem::node::LeafIndex;

        // Group from 5 members
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 5).await;

        let b = LeafIndex::unchecked(1);
        let next_epoch: u64 = 100;
        let leaf_indices: Vec<_> = groups[0]
            .state
            .public_tree
            .non_empty_leaves()
            .map(|(i, _)| i)
            .collect();

        for i in leaf_indices {
            let leaf = groups[0]
                .state
                .public_tree
                .nodes
                .borrow_as_leaf_mut(i)
                .unwrap();
            leaf.equar = 0;
            leaf.epk = next_epoch;
        }
    
        // B must be a ghost
        {
            let leaf_b = groups[0].state.public_tree.nodes.borrow_as_leaf_mut(b).unwrap();
            leaf_b.mark_as_ghost(65); // B had last update on 65 epoch
            leaf_b.epk = next_epoch - GroupState::GHOST_KEY_UPDATE_DELAY;
        }

        let mut proposals = Vec::new();
        let mut pending = Vec::new();

        let ghost_updates = groups[0]
            .update_ghost_members(&mut proposals, &mut pending, next_epoch)
            .await
            .unwrap();

        //
        assert!(
            pending.iter().any(|p| p.leaf_index == b && matches!(p.reason, super::GhostKeyReason::Rotation)),
            "expected Rotation for ghost member when epk is old enough"
        );
        assert!(
            ghost_updates.iter().any(|u| u.leaf_index == b),
            "expected a ghost leaf update for key rotation"
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_update_ghost_members_quarantines_non_ghost_based_on_epk() {
        use crate::client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION};
        use crate::group::state::GroupState;
        use crate::group::test_utils::test_n_member_group;
        use crate::tree_kem::node::LeafIndex;

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 5).await;

        let b = LeafIndex::unchecked(1);
        let next_epoch: u64 = 200;

        let leaf_indices: Vec<_> = groups[0]
            .state
            .public_tree
            .non_empty_leaves()
            .map(|(i, _)| i)
            .collect();

        for i in leaf_indices {
            let leaf = groups[0]
                .state
                .public_tree
                .nodes
                .borrow_as_leaf_mut(i)
                .unwrap();
            leaf.equar = 0;
            leaf.epk = next_epoch;
        }
        // B не ghost, но "неактивен" по epk
        {
            let leaf_b = groups[0].state.public_tree.nodes.borrow_as_leaf_mut(b).unwrap();
            leaf_b.equar = 0;
            leaf_b.epk = next_epoch - GroupState::INACTIVITY_DELAY;
        }

        let mut proposals = Vec::new();
        let mut pending = Vec::new();

        let ghost_updates = groups[0]
            .update_ghost_members(&mut proposals, &mut pending, next_epoch)
            .await
            .unwrap();

        // Должен появиться pending derivation с NewQuarantine
        assert!(
            pending.iter().any(|p| p.leaf_index == b && matches!(p.reason, super::GhostKeyReason::NewQuarantine)),
            "expected NewQuarantine for inactive non-ghost member"
        );

        // Должно появиться ghost tree-mutation, помечающее leaf как ghost (equar=next_epoch)
        let updated = ghost_updates
            .iter()
            .find(|u| u.leaf_index == b)
            .map(|u| &u.leaf_node)
            .expect("expected ghost leaf update");

        assert_eq!(updated.equar, next_epoch, "expected equar set to next_epoch");
        assert_eq!(updated.epk, next_epoch, "expected epk set to next_epoch");
        assert!(updated.is_ghost(), "expected updated leaf to be ghost");
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_public_tree_consistency() {
        use crate::client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION};
        use crate::group::test_utils::test_n_member_group;

        // groups[0] = Alice, groups[1] = Bob
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 2).await;

        //Alice commits
        let commit_output = groups[0].commit(vec![]).await.unwrap();
        let commit_msg = commit_output.commit_message;
        groups[0].apply_pending_commit().await.unwrap();

        //Bob processes commit
        groups[1].process_message(commit_msg).await.unwrap();

        //Check public tree consistency
        assert_eq!(
            groups[0].state.public_tree,
            groups[1].state.public_tree,
            "public trees diverged after Bob processed Alice's commit"
        );
        assert_eq!(
            groups[0].context().epoch,
            groups[1].context().epoch,
            "group epochs diverged after commit processing"
        );

        let roster_a = groups[0].roster().members();
        let roster_b = groups[1].roster().members();

        assert_eq!(
            roster_a, roster_b,
            "rosters diverged after commit processing"
        );

        let a0 = groups[0].roster().member_with_index(0).unwrap();
        let b0 = groups[1].roster().member_with_index(0).unwrap();
        assert_eq!(a0, b0, "member_with_index(0) diverged");

        let a1 = groups[0].roster().member_with_index(1).unwrap();
        let b1 = groups[1].roster().member_with_index(1).unwrap();
        assert_eq!(a1, b1, "member_with_index(1) diverged");
    }


    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_demo() {
        use crate::client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION};
        use crate::group::state::GroupState;
        use crate::group::test_utils::test_n_member_group;
        use crate::tree_kem::node::LeafIndex;

        // === Arrange ===
        // groups[0] = Alice (committer), groups[1] = Bob (will be quarantined / goes inactive)
        let n_members: usize = 9;
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, n_members).await;

        let alice = 0usize;
        let bob = LeafIndex::unchecked(1);


        // Buffer commits that Bob misses while inactive, so that he can replay them after recovery.
        let mut bob_buffered_commits = Vec::new();

        // === Act (1): quarantine Bob ===
        let mut quarantined_epoch: Option<u64> = None;

        let max_steps = (GroupState::INACTIVITY_DELAY as usize) * 3;
        let mut pre = Vec::new();
        let mut post = Vec::new();


        for _step in 0..max_steps {
            let out = groups[alice].commit(vec![]).await.unwrap();
            let commit_msg = out.commit_message;

            groups[alice].apply_pending_commit().await.unwrap();
            let epoch_after_apply = groups[alice].context().epoch;
            // Deliver to all other active members; Bob (inactive) does not process commits.
            
            for i in 2..n_members {
                groups[i].process_message(commit_msg.clone()).await.unwrap();
            }
            bob_buffered_commits.push((epoch_after_apply, commit_msg.clone()));
            // Check in Alice's view whether Bob is now quarantined
            let leaf_b = groups[alice]
                .state
                .public_tree
                .nodes
                .borrow_as_leaf(bob)
                .unwrap();

            if leaf_b.equar != 0 {
                quarantined_epoch = Some(leaf_b.equar);
                break;
            }
        }

        let key_epoch = quarantined_epoch.expect("Bob was not quarantined within max_steps");

        // Sanity: active members see Bob as ghost
        for i in 0..n_members {
            if i == 1 {
                continue; // Bob was inactive
            }
            let leaf_b = groups[i]
                .state
                .public_tree
                .nodes
                .borrow_as_leaf(bob)
                .unwrap();
            assert_eq!(leaf_b.equar, key_epoch, "member {} sees wrong equar", i);
            assert!(leaf_b.is_ghost(), "member {} does not see Bob as ghost", i);
            
            groups[i].cache_received_ghost_shares();
        }

        // === Act (2): Bob returns via threshold share recovery ===
        //
        // Bob contacts t active members and receives shares. In the test we simply copy
        // share holders from active members into Bob's local store (equivalent to ShareResend).
        let t = groups[alice].config.ghost_sharing_params().threshold_t as usize;
        assert!(t > 0);
        for (e, msg) in bob_buffered_commits.into_iter() {
            if e < key_epoch {
                pre.push(msg);
            } else {
                post.push(msg);
            }
        }
        assert!(!post.is_empty(), "expected at least the quarantine commit in post");
for msg in pre {
            groups[1].process_message(msg).await.unwrap();
        }
        let mut copied = 0usize;
        for donor in 0..n_members {
             if donor == 1 {
                continue; // Bob
            }
            let shares = groups[donor]
                .private_tree
                .ghost_share_holders
                .iter()
                .filter(|h| h.ghost_leaf == bob && h.key_epoch == key_epoch)
                .cloned()
                .collect::<Vec<_>>();

            for h in shares {
                groups[1].private_tree.ghost_share_holders.push(h);
            }

            // Count unique share ids now available to Bob.
            let mut uniq = std::collections::BTreeSet::new();
            for h in groups[1]
                .private_tree
                .ghost_share_holders
                .iter()
                .filter(|h| h.ghost_leaf == bob && h.key_epoch == key_epoch)
            {
                uniq.insert(h.share_id);
            }
            copied = uniq.len();
            if copied >= t {
                break;
            }
        }
        assert!(
            copied >= t,
            "insufficient unique shares copied for recovery: got {}, need {}",
            copied,
            t
        );

        let quarantine_commit = post[0].clone();
        groups[1]
            .preapply_commit_public_only(quarantine_commit.clone())
            .await
            .unwrap();
        // Recover and install Bob's ghost/self HPKE secret key so he can decrypt UpdatePath.
        groups[1]
            .recover_and_install_ghost_self_key(bob, key_epoch)
            .await
            .unwrap();

        groups[1].process_message(quarantine_commit).await.unwrap();
        for msg in post.into_iter().skip(1) {
            groups[1].process_message(msg).await.unwrap();
        }
        // === Act (3): Bob reactivates by making a self-update commit ===
        // QTreeKEM: after catch-up, the member can generate a fresh leaf key and sign it,
        // clearing equar and becoming active again.
        let out = groups[1].commit(vec![]).await.unwrap();
        let commit_msg = out.commit_message;
        groups[1].apply_pending_commit().await.unwrap();

        // Deliver Bob's commit to all other active members
        for i in 0..n_members {
            if i == 1 {
                continue;
            }
            groups[i].process_message(commit_msg.clone()).await.unwrap();
        }

        // === Assert: everyone (including Bob) now sees Bob as active (not ghost) ===
        for i in 0..n_members {
            let leaf_b = groups[i]
                .state
                .public_tree
                .nodes
                .borrow_as_leaf(bob)
                .unwrap();

            assert_eq!(leaf_b.equar, 0, "member {} still sees Bob quarantined", i);
            assert!(!leaf_b.is_ghost(), "member {} still sees Bob as ghost", i);
            assert!(leaf_b.signing_identity.is_some(), "member {} sees Bob without identity", i);
            assert!(leaf_b.signature != vec![0u8], "member {} sees Bob with ghost signature", i);
        }
    }
}
