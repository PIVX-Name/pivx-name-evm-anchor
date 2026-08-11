// Official PIVX Names EVM anchor contract (SP1 public verification proof + checkpoints)
// Website: https://pivx.name
// GitHub: https://github.com/PIVX-Name

// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice The official SP1 Verifier Interface standard (sp1-contracts)
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title PiNS Layer-2 Anchor
/// @notice Secures the PIVX Names Service sparse merkle tree state using SP1 ZK-SNARKs
contract PiNSAnchor {
    // --- STRUCTS ---
    struct RootInfo {
        uint32 blockHeight;
        bool isValid;
    }

    // --- ROLES & STATE PACKING ---
    // Slot 0 (20 bytes + 4 bytes + 1 byte = 25 bytes)
    address public owner;
    // Height on the PIVX chain that the current root covers - NOT a height on this
    // EVM chain. It is the batch's end_block_height, and `verifyRootValidity`
    // returns it as such; commitBatch requires it to strictly increase.
    uint32 public currentBlockHeight;
    bool public paused;

    // Slot 1 (20 bytes)
    address public sequencer; // The specific wallet authorized to submit batches

    // Slot 2 (20 bytes)
    address public pendingOwner; // Pending owner for 2-step ownership transfer

    // Slot 3 (20 bytes)
    address public sp1Verifier; // SP1 Gateway verifier address

    // Slot 4 (32 bytes)
    bytes32 public programVkey; // SP1 program verification key

    // Slot 5 (32 bytes)
    bytes32 public currentRoot; // Current state root

    // Slot 6
    /// @notice Maps a historically valid Merkle Root directly to its RootInfo struct
    mapping(bytes32 => RootInfo) public rootHistory;

    /// @notice Every root this contract has accepted, in commit order, genesis first.
    /// @dev Exists so a rollback can repudiate the roots it supersedes. `rootHistory`
    ///      alone cannot be walked, and without that walk `isRootValid` would keep
    ///      attesting to the very roots a rollback exists to disavow — a client
    ///      verifying a Merkle proof against a defective root would still be told the
    ///      root is good. Nothing else reads this list; it is bookkeeping for
    ///      `approveRootRollback`.
    bytes32[] public rootChain;

    /// @notice Program upgrade proposed by the sequencer, awaiting owner approval.
    /// @dev bytes32(0) means "none pending"; a zero vkey is rejected everywhere anyway.
    bytes32 public pendingProgramVkey;

    /// @notice Root rollback proposed by the sequencer, awaiting owner approval.
    /// @dev bytes32(0) means "none pending".
    bytes32 public pendingRollbackRoot;

    // --- CUSTOM ERRORS ---
    error Unauthorized();
    error NotSequencer();
    error NotPendingOwner();
    error EnforcedPause();
    error ExpectedPause();
    error InvalidOldRoot(bytes32 expected, bytes32 provided);
    error InvalidBlockHeight(uint32 current, uint32 provided);
    error InvalidAddress();
    error InvalidVKey();
    error InvalidRoot();
    error InvalidPublicValues();
    error NoPendingProposal();
    error ProposalMismatch();
    error UnknownRoot();

    // --- EVENTS ---
    // Every two-step flow emits on all three outcomes - proposed, applied, rejected - and
    // each of those carries the address that caused it, so the full authorisation trail of
    // a privileged change can be reconstructed from logs alone, without joining against
    // transaction senders.
    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint32 endBlockHeight);
    event ProgramUpgraded(bytes32 indexed oldVkey, bytes32 indexed newVkey, address indexed approver);
    event ProgramUpgradeProposed(bytes32 indexed newVkey, address indexed proposer);
    event ProgramUpgradeReverted(bytes32 indexed rejectedVkey, address indexed rejectedBy);
    event RootRollbackProposed(bytes32 indexed targetRoot, address indexed proposer);
    event RootRollbackReverted(bytes32 indexed rejectedRoot, address indexed rejectedBy);
    event RootRolledBack(bytes32 indexed fromRoot, bytes32 indexed toRoot, address indexed approver, uint32 toBlockHeight);
    /// @notice A root a rollback disavowed. `isRootValid` returns false for it from here on.
    event RootInvalidated(bytes32 indexed root, uint32 blockHeight);
    event SequencerUpdated(address indexed oldSequencer, address indexed newSequencer);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCanceled(address indexed previousOwner, address indexed canceledOwner, address indexed canceledBy);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address account);
    event Unpaused(address account);

    // --- MODIFIERS ---
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlySequencer() {
        // Owner serves as a fallback sequencer just in case
        if (msg.sender != sequencer && msg.sender != owner) revert NotSequencer();
        _;
    }

    /// @dev Strictly the sequencer. Unlike `onlySequencer` the owner is NOT a fallback:
    ///      these are the proposing half of a two-step flow whose whole purpose is that a
    ///      second, different key must approve.
    modifier onlySequencerStrict() {
        if (msg.sender != sequencer) revert NotSequencer();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert EnforcedPause();
        _;
    }

    modifier whenPaused() {
        if (!paused) revert ExpectedPause();
        _;
    }

    /// @param _sequencer Batch-submitting wallet. MUST differ from the deployer: the
    ///        two-step upgrade and rollback flows below require two distinct parties,
    ///        and collapse to a single point of control if they are the same key.
    /// @param _genesisRoot State root at `_genesisBlockHeight`. bytes32(0) is ACCEPTED here
    ///        and nowhere else: in the compact SMT an empty subtree is [0u8;32] at every
    ///        height, so the root of an empty tree is bytes32(0). Anchoring from the
    ///        registrar wallet's birthday - the block before which no service transaction
    ///        can exist - means genesis legitimately is the empty registry, and any third
    ///        party replaying the chain from that height computes bytes32(0) too. Seeding a
    ///        synthetic leaf just to obtain a non-zero root would instead force every
    ///        independent indexer to reproduce that seed, putting a special case into the
    ///        replication that the whole trust model rests on.
    constructor(
        address _sp1Verifier,
        bytes32 _programVkey,
        bytes32 _genesisRoot,
        uint32 _genesisBlockHeight,
        address _sequencer
    ) {
        if (_sp1Verifier == address(0)) revert InvalidAddress();
        if (_programVkey == bytes32(0)) revert InvalidVKey();
        if (_sequencer == address(0) || _sequencer == msg.sender) revert InvalidAddress();

        owner = msg.sender;
        sequencer = _sequencer;
        sp1Verifier = _sp1Verifier;
        programVkey = _programVkey;

        currentRoot = _genesisRoot;
        currentBlockHeight = _genesisBlockHeight;

        rootHistory[_genesisRoot] = RootInfo({
            blockHeight: _genesisBlockHeight,
            isValid: true
        });
        // Genesis anchors the chain. A rollback walk therefore always terminates on a
        // root that exists, and can never empty the list.
        rootChain.push(_genesisRoot);

        emit OwnershipTransferred(address(0), msg.sender);
        emit SequencerUpdated(address(0), _sequencer);
        emit RootUpdated(bytes32(0), _genesisRoot, _genesisBlockHeight);
    }

    /// @notice Submits a new batch of PiNS transactions from the Sequencer
    /// @param proofBytes The proof generated by SP1 host prover
    /// @param publicValues The ABI encoded public values (oldRoot, newRoot, endBlockHeight)
    function commitBatch(bytes calldata proofBytes, bytes calldata publicValues) external onlySequencer whenNotPaused {
        // Strict payload validation (3 * 32 bytes = 96 bytes expected)
        if (publicValues.length != 96) revert InvalidPublicValues();

        // 1. Decode the public values exactly as your Rust Host script encoded them
        (bytes32 oldRoot, bytes32 newRoot, uint32 endBlockHeight) = abi.decode(
            publicValues,
            (bytes32, bytes32, uint32)
        );

        // A committed root is never bytes32(0): that value is the empty tree, reachable
        // only as the genesis state, and a batch that emptied the entire registry is a
        // defect rather than a transition worth anchoring.
        if (newRoot == bytes32(0)) revert InvalidRoot();

        // 2. Enforce absolute chronological progression using Gas-Efficient Custom Errors
        if (oldRoot != currentRoot) revert InvalidOldRoot(currentRoot, oldRoot);
        if (endBlockHeight <= currentBlockHeight) revert InvalidBlockHeight(currentBlockHeight, endBlockHeight);

        // 3. Cryptographically verify the Zero-Knowledge Proof via SP1 Verifier Gateway
        _verifyProof(publicValues, proofBytes);

        // 4. Update the official state
        currentRoot = newRoot;
        currentBlockHeight = endBlockHeight;

        // 5. Save the root mapped to its PIVX block height and validity marker
        rootHistory[newRoot] = RootInfo({
            blockHeight: endBlockHeight,
            isValid: true
        });
        rootChain.push(newRoot);

        emit RootUpdated(oldRoot, newRoot, endBlockHeight);
    }

    /// @notice Checks if a specific root is valid and what PIVX block height it belongs to
    /// @param _root The Merkle root hash to verify
    /// @return isValid True if the root was confirmed on-chain
    /// @return blockHeight The PIVX block height at which this root was confirmed
    function verifyRootValidity(bytes32 _root) external view returns (bool isValid, uint32 blockHeight) {
        RootInfo memory info = rootHistory[_root];
        return (info.isValid, info.blockHeight);
    }

    /// @notice Helper to check root validity directly
    /// @param _root The Merkle root hash to check
    /// @return True if valid, false otherwise
    function isRootValid(bytes32 _root) external view returns (bool) {
        return rootHistory[_root].isValid;
    }

    /// @dev Internal verification hook; overridden by MockZNSAnchor for test bypass.
    ///      `view` deliberately: it matches ISP1Verifier.verifyProof's own mutability and
    ///      makes it structurally impossible for a compromised or swapped-out verifier to
    ///      re-enter commitBatch, rather than relying on statement ordering to be safe.
    function _verifyProof(bytes calldata publicValues, bytes calldata proofBytes) internal view virtual {
        ISP1Verifier(sp1Verifier).verifyProof(programVkey, publicValues, proofBytes);
    }

    // ==========================================
    // ADMIN UPGRADEABILITY & EMERGENCY MANAGEMENT
    // ==========================================

    /// @notice Triggers emergency pause for batch processing
    function pause() external onlyOwner whenNotPaused {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpauses batch processing
    function unpause() external onlyOwner whenPaused {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ------------------------------------------------------------------
    // TWO-STEP PROGRAM UPGRADE
    //
    // The verification key decides which circuit — and therefore which protocol rules —
    // this contract will accept proofs from. A single key able to change it in one
    // transaction could silently change the rules, so the change is split across two
    // distinct parties: the sequencer proposes, the owner approves or rejects.
    // ------------------------------------------------------------------

    /// @notice Sequencer proposes a new program verification key.
    /// @dev Owner is deliberately not a fallback here; see `onlySequencerStrict`.
    function proposeProgramUpgrade(bytes32 _newProgramVkey) external onlySequencerStrict {
        if (_newProgramVkey == bytes32(0)) revert InvalidVKey();
        pendingProgramVkey = _newProgramVkey;
        emit ProgramUpgradeProposed(_newProgramVkey, msg.sender);
    }

    /// @notice Owner approves the pending upgrade, applying it.
    /// @param _expectedVkey The key the owner intends to approve.
    /// @dev The caller states the value it is approving, so a sequencer cannot replace
    ///      the proposal between the owner inspecting it and the approval landing.
    function approveProgramUpgrade(bytes32 _expectedVkey) external onlyOwner {
        bytes32 pending = pendingProgramVkey;
        if (pending == bytes32(0)) revert NoPendingProposal();
        if (pending != _expectedVkey) revert ProposalMismatch();

        bytes32 oldVkey = programVkey;
        programVkey = pending;
        pendingProgramVkey = bytes32(0);
        emit ProgramUpgraded(oldVkey, pending, msg.sender);
    }

    /// @notice Owner rejects the pending upgrade, invalidating it.
    function revertProgramUpgrade() external onlyOwner {
        bytes32 pending = pendingProgramVkey;
        if (pending == bytes32(0)) revert NoPendingProposal();
        pendingProgramVkey = bytes32(0);
        emit ProgramUpgradeReverted(pending, msg.sender);
    }

    // ------------------------------------------------------------------
    // TWO-STEP ROOT ROLLBACK
    //
    // Recovery path for a checkpoint that can never be built on again: a PIVX reorg
    // deeper than the registrar's confirmation threshold, a circuit defect, or a batch
    // committed with an absurd block height. Without it the only remedy is redeploying
    // and repointing every client and indexer.
    //
    // Deliberately constrained: the target must be a root this contract itself accepted
    // before, and its height is taken from that record rather than supplied, so a
    // rollback can only ever move the chain to a state it already attested to.
    // ------------------------------------------------------------------

    /// @notice Sequencer proposes rolling the state back to a previously valid root.
    function proposeRootRollback(bytes32 _targetRoot) external onlySequencerStrict {
        if (_targetRoot == bytes32(0)) revert InvalidRoot();
        if (!rootHistory[_targetRoot].isValid) revert UnknownRoot();
        pendingRollbackRoot = _targetRoot;
        emit RootRollbackProposed(_targetRoot, msg.sender);
    }

    /// @notice Owner approves the pending rollback and applies it.
    /// @param _expectedRoot The root the owner intends to roll back to.
    /// @dev Requires the contract to be paused: rolling the state back while batches are
    ///      still being accepted would race with an in-flight commit.
    function approveRootRollback(bytes32 _expectedRoot) external onlyOwner whenPaused {
        bytes32 pending = pendingRollbackRoot;
        if (pending == bytes32(0)) revert NoPendingProposal();
        if (pending != _expectedRoot) revert ProposalMismatch();

        RootInfo memory info = rootHistory[pending];
        // Re-checked rather than trusted from propose time: an earlier rollback may
        // already have disavowed this target, and a proposal must not outlive it.
        if (!info.isValid) revert UnknownRoot();

        bytes32 fromRoot = currentRoot;

        // Walk the chain back from the tip, repudiating every root committed after the
        // target. A root that stayed valid here would still satisfy `isRootValid`, so a
        // Merkle proof against the defective state this rollback exists to undo would
        // keep verifying for every client — the rollback would move the head and change
        // nothing an outside observer checks.
        //
        // The target is guaranteed to be in the list (it is valid, and every valid root
        // was pushed when committed), so this terminates before exhausting it. Cost is
        // linear in the number of batches being undone; a very deep rollback can be
        // split into several shallower ones, since every intermediate root is itself a
        // valid target.
        uint256 n = rootChain.length;
        while (n > 0) {
            bytes32 top = rootChain[n - 1];
            if (top == pending) break;
            emit RootInvalidated(top, rootHistory[top].blockHeight);
            delete rootHistory[top];
            rootChain.pop();
            unchecked { --n; }
        }

        currentRoot = pending;
        currentBlockHeight = info.blockHeight;
        pendingRollbackRoot = bytes32(0);

        emit RootRolledBack(fromRoot, pending, msg.sender, info.blockHeight);
    }

    /// @notice Owner rejects the pending rollback.
    function revertRootRollback() external onlyOwner {
        bytes32 pending = pendingRollbackRoot;
        if (pending == bytes32(0)) revert NoPendingProposal();
        pendingRollbackRoot = bytes32(0);
        emit RootRollbackReverted(pending, msg.sender);
    }

    /// @notice Changes the wallet authorized to submit ZK proofs
    /// @dev Discards any proposal the outgoing sequencer left pending. The main reason to
    ///      rotate this key is that it was lost or compromised, and a proposal made by the
    ///      key being revoked must not stay approvable after the revocation - otherwise
    ///      locking an attacker out would leave their proposed vkey or rollback target
    ///      sitting there, one owner mistake away from being applied. Cancellation is
    ///      reported through the same Reverted events as an explicit rejection; the
    ///      accompanying SequencerUpdated in the same transaction gives the reason.
    function updateSequencer(address _newSequencer) external onlyOwner {
        // Same rule the constructor enforces, for the same reason: the two-step upgrade
        // and rollback flows exist so that a second, DIFFERENT key must approve. Pointing
        // the sequencer at the owner would let one key both propose and approve a new
        // vkey — that is, silently change which circuit's rules this contract accepts.
        if (_newSequencer == address(0) || _newSequencer == owner) revert InvalidAddress();
        address oldSequencer = sequencer;
        sequencer = _newSequencer;
        emit SequencerUpdated(oldSequencer, _newSequencer);

        bytes32 pendingVkey = pendingProgramVkey;
        if (pendingVkey != bytes32(0)) {
            pendingProgramVkey = bytes32(0);
            emit ProgramUpgradeReverted(pendingVkey, msg.sender);
        }

        bytes32 pendingRoot = pendingRollbackRoot;
        if (pendingRoot != bytes32(0)) {
            pendingRollbackRoot = bytes32(0);
            emit RootRollbackReverted(pendingRoot, msg.sender);
        }
    }

    /// @notice Updates the SP1 Gateway Address if Succinct Network pushes an official contract upgrade
    function updateVerifier(address _newVerifier) external onlyOwner {
        if (_newVerifier == address(0)) revert InvalidAddress();
        address oldVerifier = sp1Verifier;
        sp1Verifier = _newVerifier;
        emit VerifierUpdated(oldVerifier, _newVerifier);
    }

    /// @notice Starts 2-step ownership transfer to a new address
    /// @dev Calling this again while an offer is outstanding replaces it, exactly as
    ///      re-proposing does in the upgrade and rollback flows; the new
    ///      OwnershipTransferStarted supersedes the previous one.
    function transferOwnership(address _newOwner) external onlyOwner {
        // Rejected at proposal time as well as on acceptance, so the mistake surfaces to
        // the owner making it rather than to the recipient. The acceptance-side check is
        // the binding one, since the sequencer can change while an offer is outstanding.
        if (_newOwner == address(0) || _newOwner == sequencer) revert InvalidAddress();
        pendingOwner = _newOwner;
        emit OwnershipTransferStarted(owner, _newOwner);
    }

    /// @notice Owner withdraws an ownership offer that has not been accepted yet.
    /// @dev Without this, an offer sent to a wrong or compromised address would stay live
    ///      indefinitely: transferOwnership(address(0)) reverts on InvalidAddress, so the
    ///      only other way to neutralise it is re-pointing it at some other address.
    function cancelOwnershipTransfer() external onlyOwner {
        address pending = pendingOwner;
        if (pending == address(0)) revert NoPendingProposal();
        pendingOwner = address(0);
        emit OwnershipTransferCanceled(owner, pending, msg.sender);
    }

    /// @notice Nominated owner refuses the transfer, clearing it.
    /// @dev The counterpart to acceptOwnership, so the recipient can close out an offer
    ///      it does not want instead of leaving it pending for the owner to clean up.
    function declineOwnership() external {
        address pending = pendingOwner;
        if (msg.sender != pending) revert NotPendingOwner();
        pendingOwner = address(0);
        emit OwnershipTransferCanceled(owner, pending, msg.sender);
    }

    /// @notice Accepts pending ownership transfer
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        // The binding half of the separation rule. Checking only at transferOwnership
        // time would be bypassable: updateSequencer could point the sequencer at the
        // pending owner after the offer was made, and acceptance would then collapse
        // both roles onto one key.
        if (msg.sender == sequencer) revert InvalidAddress();
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }
}
