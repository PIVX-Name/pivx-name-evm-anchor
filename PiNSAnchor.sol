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
    /// @dev Where a root sits in the chain, and the PIVX height it covers. Deliberately no
    ///      validity flag: a root is valid exactly while the chain still holds it at its
    ///      index (see `_isValid`), so a rollback invalidates everything above its target by
    ///      moving `tipIndex` alone, with nothing to walk or delete.
    struct RootInfo {
        uint32 blockHeight;
        uint32 index;
    }

    // --- ROLES & STATE PACKING ---
    // Slot 0 (20 bytes + 4 bytes + 1 byte + 4 bytes = 29 bytes)
    address public owner;
    // Height on the PIVX chain that the current root covers - NOT a height on this
    // EVM chain. It is the batch's end_block_height, and `verifyRootValidity`
    // returns it as such; commitBatch requires it to strictly increase.
    uint32 public currentBlockHeight;
    bool public paused;
    /// @notice Advances whenever the anchored state changes by anything other than a proven
    ///         batch under unchanged rules: a rules change, or a rollback.
    /// @dev Starts at 1 and goes up by one each time, never down. Those are the only two
    ///      ways the current root can move without a proof under rules a client has
    ///      already reviewed - new rules decide what counts as proven, and a rollback makes
    ///      an older state current again, re-pointing any name changed since without its
    ///      owner's signature. A client pins the epochs it has reviewed and refuses a root
    ///      under any other, so neither reaches it until the client itself is updated. The
    ///      value must only grow: comparing `programVkey` and `sp1Verifier` instead would
    ///      miss a change and its reversal, with a forged root committed in between.
    uint32 public epoch;

    // Slot 1 (20 bytes + 4 bytes = 24 bytes)
    address public sequencer; // The specific wallet authorized to submit batches
    /// @notice Index of the current root in the chain; the genesis root is index 0.
    /// @dev Packed beside `sequencer`, which every commit reads anyway for authorisation.
    uint32 public tipIndex;

    // Slot 2 (20 bytes)
    address public pendingOwner; // Pending owner for 2-step ownership transfer

    // Slot 3 (20 bytes)
    address public sp1Verifier; // SP1 Gateway verifier address

    // Slot 4 (32 bytes)
    bytes32 public programVkey; // SP1 program verification key

    /// @notice The chain of accepted roots by index, genesis (bytes32(0)) at 0. Entries above
    ///         `tipIndex` are left over from before a rollback and are not part of it.
    mapping(uint256 => bytes32) public rootAt;

    /// @dev Index and height of every root ever accepted - including roots a rollback has
    ///      since disavowed, which is why it is private: whether an entry exists says
    ///      nothing about whether the root is valid. Use `isRootValid` or
    ///      `verifyRootValidity`.
    mapping(bytes32 => RootInfo) private rootHistory;

    /// @notice Rules change proposed by the sequencer: the program key it would install.
    /// @dev bytes32(0) means "none pending"; a zero vkey is rejected everywhere anyway.
    bytes32 public pendingRulesVkey;

    /// @notice The verifier the pending rules change would install. Packs with the next
    ///         field into one slot (20 + 8 bytes).
    address public pendingRulesVerifier;

    /// @notice When the approved rules change may be activated (unix seconds), or 0 while
    ///         it is only proposed.
    uint64 public rulesChangeActivatesAt;

    /// @notice Root rollback proposed by the sequencer, awaiting owner approval.
    /// @dev bytes32(0) means "none pending".
    bytes32 public pendingRollbackRoot;

    /// @notice The shortest notice any deployment may give of a rules change.
    uint64 public constant MIN_RULES_TIMELOCK = 7 days;

    /// @notice The longest. Bounded so a mistyped deployment cannot overflow the activation
    ///         time and freeze the rules for good.
    uint64 public constant MAX_RULES_TIMELOCK = 90 days;

    /// @notice How long an approved rules change waits before it can take effect, fixed at
    ///         deployment. Long enough for clients to review the new program and ship a
    ///         release that accepts its version before the old one stops being current.
    uint64 public immutable rulesTimelock;

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
    error InvalidTimelock();
    error ChangeAlreadyScheduled();
    error NotScheduled();
    error TimelockActive(uint64 activatesAt);
    error NoChange();

    // --- EVENTS ---
    // Every privileged flow emits on each of its outcomes - proposed, approved or scheduled,
    // applied, rejected - and each of those carries the address that caused it, so the full
    // authorisation trail of a privileged change can be reconstructed from logs alone,
    // without joining against transaction senders.
    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint32 endBlockHeight);
    event RulesChangeProposed(bytes32 indexed newVkey, address indexed newVerifier, address indexed proposer);
    event RulesChangeScheduled(bytes32 indexed newVkey, address indexed newVerifier, address indexed approver, uint64 activatesAt);
    event RulesChangeReverted(bytes32 indexed rejectedVkey, address indexed rejectedVerifier, address indexed rejectedBy);
    event RulesChanged(
        bytes32 indexed oldVkey,
        bytes32 indexed newVkey,
        address oldVerifier,
        address newVerifier,
        address indexed activatedBy
    );
    /// @notice `epoch` advanced - after a rules change or a rollback, in the same
    ///         transaction. This is the one event a pinning client needs to watch.
    event EpochAdvanced(uint32 indexed newEpoch);
    event RootRollbackProposed(bytes32 indexed targetRoot, address indexed proposer);
    event RootRollbackReverted(bytes32 indexed rejectedRoot, address indexed rejectedBy);
    /// @notice A rollback. The `batchesUndone` roots committed after `toRoot` are disavowed:
    ///         `isRootValid` returns false for each of them from here on. Which roots they
    ///         were can be read from the `RootUpdated` events that committed them.
    event RootRolledBack(
        bytes32 indexed fromRoot,
        bytes32 indexed toRoot,
        address indexed approver,
        uint32 toBlockHeight,
        uint32 batchesUndone
    );
    event SequencerUpdated(address indexed oldSequencer, address indexed newSequencer);
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

    /// @notice Genesis is always the empty registry, whose root is bytes32(0): in the compact
    ///         SMT an empty subtree is [0u8;32] at every height. Anchoring from the registrar
    ///         wallet's birthday - the block before which no service transaction can exist -
    ///         means every later root is reached by proven batches from a state anyone can
    ///         reproduce, and any third party replaying the chain from that height computes
    ///         bytes32(0) too. Taking the genesis root as a parameter would let a deployment
    ///         start from a state no proof backs. Seeding a synthetic leaf just to obtain a
    ///         non-zero root would instead force every independent indexer to reproduce that
    ///         seed, putting a special case into the replication that the whole trust model
    ///         rests on.
    /// @param _sp1Verifier The SP1 verifier (gateway) contract. Must have code.
    /// @param _genesisBlockHeight The registrar wallet's birthday on PIVX: the height the
    ///        empty genesis state covers.
    /// @param _sequencer Batch-submitting wallet. MUST differ from the deployer: the
    ///        two-step rules and rollback flows below require two distinct keys, and
    ///        collapse to a single point of control if they are the same key.
    /// @param _rulesTimelock Seconds an approved rules change waits before it can take
    ///        effect; between `MIN_RULES_TIMELOCK` and `MAX_RULES_TIMELOCK`. Immutable, so
    ///        the notice clients get cannot be shortened later.
    constructor(
        address _sp1Verifier,
        bytes32 _programVkey,
        uint32 _genesisBlockHeight,
        address _sequencer,
        uint64 _rulesTimelock
    ) {
        if (_sp1Verifier.code.length == 0) revert InvalidAddress();
        if (_programVkey == bytes32(0)) revert InvalidVKey();
        if (_sequencer == address(0) || _sequencer == msg.sender) revert InvalidAddress();
        if (_rulesTimelock < MIN_RULES_TIMELOCK || _rulesTimelock > MAX_RULES_TIMELOCK) {
            revert InvalidTimelock();
        }

        owner = msg.sender;
        sequencer = _sequencer;
        sp1Verifier = _sp1Verifier;
        programVkey = _programVkey;
        epoch = 1;
        rulesTimelock = _rulesTimelock;

        // The chain starts as just the empty registry: rootAt[0] and tipIndex are already
        // zero. Genesis sits at index 0, which no rollback can move below, so it is valid
        // for good.
        currentBlockHeight = _genesisBlockHeight;
        rootHistory[bytes32(0)] = RootInfo({ blockHeight: _genesisBlockHeight, index: 0 });

        emit OwnershipTransferred(address(0), msg.sender);
        emit SequencerUpdated(address(0), _sequencer);
        emit RootUpdated(bytes32(0), bytes32(0), _genesisBlockHeight);
    }

    /// @notice Submits a new batch of PiNS transactions from the Sequencer
    /// @param proofBytes The proof generated by SP1 host prover
    /// @param publicValues The ABI encoded public values (oldRoot, newRoot, endBlockHeight)
    function commitBatch(bytes calldata proofBytes, bytes calldata publicValues) external onlySequencer whenNotPaused {
        // Strict payload validation (3 * 32 bytes = 96 bytes expected)
        if (publicValues.length != 96) revert InvalidPublicValues();

        // 1. Decode the public values exactly as the SP1 program commits them
        //    (`BatchResultABI` in pivx-name-prover/program/src/main.rs). The decoder
        //    rejects a height word with any bit set above the low 32.
        (bytes32 oldRoot, bytes32 newRoot, uint32 endBlockHeight) = abi.decode(
            publicValues,
            (bytes32, bytes32, uint32)
        );

        // A committed root is never bytes32(0): that value is the empty tree, reachable
        // only as the genesis state, and a batch that emptied the entire registry is a
        // defect rather than a transition worth anchoring.
        if (newRoot == bytes32(0)) revert InvalidRoot();
        // Nor is it one already anchored, the current root included. Every operation
        // raises a name's nonce, so an honest batch can never reproduce an earlier state;
        // accepting one would give the same root two indexes, and its record could then
        // name only one of them. A root a rollback disavowed is no longer valid, so an
        // honest re-commit of the same batch after a rollback is still accepted.
        if (_isValid(newRoot)) revert InvalidRoot();

        // 2. Enforce absolute chronological progression using Gas-Efficient Custom Errors
        uint32 tip = tipIndex;
        bytes32 current = rootAt[tip];
        if (oldRoot != current) revert InvalidOldRoot(current, oldRoot);
        if (endBlockHeight <= currentBlockHeight) revert InvalidBlockHeight(currentBlockHeight, endBlockHeight);

        // 3. Cryptographically verify the Zero-Knowledge Proof via SP1 Verifier Gateway
        _verifyProof(publicValues, proofBytes);

        // 4. Extend the chain. After a rollback this overwrites the disavowed root that
        //    held the next index, which is what keeps that root invalid for good.
        uint32 next = tip + 1;
        rootAt[next] = newRoot;
        tipIndex = next;
        currentBlockHeight = endBlockHeight;

        // 5. Record where the root sits and the PIVX height it covers
        rootHistory[newRoot] = RootInfo({ blockHeight: endBlockHeight, index: next });

        emit RootUpdated(oldRoot, newRoot, endBlockHeight);
    }

    /// @notice Checks if a specific root is valid and what PIVX block height it belongs to
    /// @param _root The Merkle root hash to verify
    /// @return isValid True if the root was confirmed on-chain and no rollback has disavowed it
    /// @return blockHeight The PIVX block height at which this root was confirmed; 0 when
    ///         the root is not valid
    function verifyRootValidity(bytes32 _root) external view returns (bool isValid, uint32 blockHeight) {
        if (!_isValid(_root)) return (false, 0);
        return (true, rootHistory[_root].blockHeight);
    }

    /// @notice Helper to check root validity directly
    /// @param _root The Merkle root hash to check
    /// @return True if valid, false otherwise
    function isRootValid(bytes32 _root) external view returns (bool) {
        return _isValid(_root);
    }

    /// @notice The current state root.
    function currentRoot() public view returns (bytes32) {
        return rootAt[tipIndex];
    }

    /// @dev Valid means the chain still holds this root at its recorded index. A root above
    ///      the tip was disavowed by a rollback; one whose index has since been reused by a
    ///      later commit was disavowed and then built over. An unknown root reads as index
    ///      0, which holds genesis, so it is never mistaken for valid - and genesis itself,
    ///      at index 0, always is.
    function _isValid(bytes32 _root) private view returns (bool) {
        RootInfo memory info = rootHistory[_root];
        // Index 0 only ever holds genesis, so answer it without reading the chain. This
        // is the path every new root takes in `commitBatch`, and it saves a cold read.
        if (info.index == 0) return _root == bytes32(0);
        return info.index <= tipIndex && rootAt[info.index] == _root;
    }

    /// @notice The current root together with the epoch it belongs to, in one read.
    /// @dev One call so both values come from the same block. Read separately, a client
    ///      could see the root from after a rules change or rollback and the epoch from
    ///      before it.
    /// @return root The current state root
    /// @return blockHeight The PIVX block height that root covers
    /// @return currentEpoch The `epoch` in force
    function anchoredState() external view returns (bytes32 root, uint32 blockHeight, uint32 currentEpoch) {
        return (rootAt[tipIndex], currentBlockHeight, epoch);
    }

    /// @dev Internal verification hook; overridden by MockPiNSAnchor for test bypass.
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
    // TIMELOCKED RULES CHANGE
    //
    // The verifier and the verification key together decide which circuit - and therefore
    // which protocol rules - this contract will accept proofs from. They change together,
    // through one flow, and every change takes effect only after `rulesTimelock`:
    //
    //   sequencer proposes  ->  owner approves (starts the clock)  ->  anyone activates
    //
    // Splitting propose and approve across two keys is not enough on its own: the owner
    // appoints the sequencer, so both halves can end up with one party. What makes a rules
    // change safe for clients is that it is announced in advance and advances `epoch`,
    // which clients pin - a new program reaches a client only once that client has been
    // updated to accept it. A change and its reversal are two epochs, never a return to
    // the old one.
    //
    // The verifier is part of the same flow rather than a separate single-step setter: a
    // verifier that accepts anything is as much a change of rules as a new program.
    // ------------------------------------------------------------------

    /// @notice Sequencer proposes new rules: a program key and the verifier to check it.
    /// @dev Owner is deliberately not a fallback here; see `onlySequencerStrict`. Pass the
    ///      current value for whichever of the two is not changing; proposing both current
    ///      values is refused, since it would advance the epoch - and halt every pinned
    ///      client until it updates - for no change at all. The verifier must have code: an
    ///      address without any would make every later batch revert. Replaces any proposal
    ///      that has not been approved yet, but not one already scheduled - that has to be
    ///      reverted first, so an approved change cannot be swapped out from under its
    ///      notice period.
    function proposeRulesChange(bytes32 _newVkey, address _newVerifier) external onlySequencerStrict {
        if (_newVkey == bytes32(0)) revert InvalidVKey();
        if (_newVerifier.code.length == 0) revert InvalidAddress();
        if (_newVkey == programVkey && _newVerifier == sp1Verifier) revert NoChange();
        if (rulesChangeActivatesAt != 0) revert ChangeAlreadyScheduled();
        pendingRulesVkey = _newVkey;
        pendingRulesVerifier = _newVerifier;
        emit RulesChangeProposed(_newVkey, _newVerifier, msg.sender);
    }

    /// @notice Owner approves the pending proposal, which starts its timelock.
    /// @param _expectedVkey The program key the owner intends to approve.
    /// @param _expectedVerifier The verifier the owner intends to approve.
    /// @dev The caller states the values it is approving, so a sequencer cannot replace
    ///      the proposal between the owner inspecting it and the approval landing.
    function approveRulesChange(bytes32 _expectedVkey, address _expectedVerifier) external onlyOwner {
        bytes32 pendingVkey = pendingRulesVkey;
        if (pendingVkey == bytes32(0)) revert NoPendingProposal();
        if (rulesChangeActivatesAt != 0) revert ChangeAlreadyScheduled();
        if (pendingVkey != _expectedVkey || pendingRulesVerifier != _expectedVerifier) revert ProposalMismatch();

        uint64 activatesAt = uint64(block.timestamp) + rulesTimelock;
        rulesChangeActivatesAt = activatesAt;
        emit RulesChangeScheduled(pendingVkey, _expectedVerifier, msg.sender, activatesAt);
    }

    /// @notice Applies an approved rules change once its timelock has passed.
    /// @dev Callable by anyone: the decision was made at approval, and the delay is only
    ///      notice. Leaving activation to the owner would let it hold an approved change
    ///      back and spring it at a moment of its choosing.
    function activateRulesChange() external {
        uint64 activatesAt = rulesChangeActivatesAt;
        if (activatesAt == 0) revert NotScheduled();
        if (block.timestamp < activatesAt) revert TimelockActive(activatesAt);

        bytes32 oldVkey = programVkey;
        address oldVerifier = sp1Verifier;
        bytes32 newVkey = pendingRulesVkey;
        address newVerifier = pendingRulesVerifier;

        programVkey = newVkey;
        sp1Verifier = newVerifier;
        _clearRulesChange();

        emit RulesChanged(oldVkey, newVkey, oldVerifier, newVerifier, msg.sender);
        _advanceEpoch();
    }

    /// @notice Owner rejects the pending rules change, whether proposed or already scheduled.
    function revertRulesChange() external onlyOwner {
        bytes32 pendingVkey = pendingRulesVkey;
        if (pendingVkey == bytes32(0)) revert NoPendingProposal();
        address pendingVerifier = pendingRulesVerifier;
        _clearRulesChange();
        emit RulesChangeReverted(pendingVkey, pendingVerifier, msg.sender);
    }

    function _clearRulesChange() private {
        pendingRulesVkey = bytes32(0);
        pendingRulesVerifier = address(0);
        rulesChangeActivatesAt = 0;
    }

    function _advanceEpoch() private {
        uint32 newEpoch = epoch + 1;
        epoch = newEpoch;
        emit EpochAdvanced(newEpoch);
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
    //
    // It still re-points every name changed after the target - back to a previous
    // address, or a previous owner after a sale - without any signature from those names'
    // owners, and the owner can drive it alone through a sequencer key it appoints. So a
    // rollback advances `epoch`: pinned clients stop resolving until they have reviewed it.
    // Rollbacks exist for emergencies - a reorg past the confirmation threshold, a circuit
    // defect - where a pause in name payments is the safe outcome anyway.
    // ------------------------------------------------------------------

    /// @notice Sequencer proposes rolling the state back to a previously valid root.
    /// @dev Not the current root: that would move nothing and still advance the epoch.
    function proposeRootRollback(bytes32 _targetRoot) external onlySequencerStrict {
        if (_targetRoot == bytes32(0) || _targetRoot == currentRoot()) revert InvalidRoot();
        if (!_isValid(_targetRoot)) revert UnknownRoot();
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

        // Cannot fail while a single pending slot exists - only approving a rollback
        // disavows roots, and that clears the slot - but everything below depends on the
        // target still being in the chain below the tip, so it is checked, not assumed.
        if (!_isValid(pending)) revert UnknownRoot();
        RootInfo memory info = rootHistory[pending];

        uint32 fromIndex = tipIndex;
        bytes32 fromRoot = rootAt[fromIndex];

        // Moving the tip back disavows every root above the target in one step: each still
        // records its old index, which now lies above the tip, so `isRootValid` returns
        // false for it - and keeps doing so once later commits reuse that index. A root
        // that stayed valid would still satisfy `isRootValid`, so a Merkle proof against
        // the defective state this rollback exists to undo would keep verifying for every
        // client. Constant cost however deep the rollback.
        tipIndex = info.index;
        currentBlockHeight = info.blockHeight;
        pendingRollbackRoot = bytes32(0);

        emit RootRolledBack(fromRoot, pending, msg.sender, info.blockHeight, fromIndex - info.index);
        _advanceEpoch();
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
    ///      sitting there, one owner mistake away from being applied. That includes a
    ///      rules change the owner has already approved: its notice period is running,
    ///      but the proposal behind it still came from the key being revoked. Cancellation
    ///      is reported through the same Reverted events as an explicit rejection; the
    ///      accompanying SequencerUpdated in the same transaction gives the reason.
    function updateSequencer(address _newSequencer) external onlyOwner {
        // Same rule the constructor enforces, for the same reason: the two-step rules and
        // rollback flows exist so that a second, DIFFERENT key must approve. Pointing the
        // sequencer at the owner would let one key both propose and approve. The timelock
        // and the epoch would still stand between that key and any client, but there is no
        // reason to give up the second key on top.
        if (_newSequencer == address(0) || _newSequencer == owner) revert InvalidAddress();
        address oldSequencer = sequencer;
        sequencer = _newSequencer;
        emit SequencerUpdated(oldSequencer, _newSequencer);

        bytes32 pendingVkey = pendingRulesVkey;
        if (pendingVkey != bytes32(0)) {
            address pendingVerifier = pendingRulesVerifier;
            _clearRulesChange();
            emit RulesChangeReverted(pendingVkey, pendingVerifier, msg.sender);
        }

        bytes32 pendingRoot = pendingRollbackRoot;
        if (pendingRoot != bytes32(0)) {
            pendingRollbackRoot = bytes32(0);
            emit RootRollbackReverted(pendingRoot, msg.sender);
        }
    }

    /// @notice Starts 2-step ownership transfer to a new address
    /// @dev Calling this again while an offer is outstanding replaces it, exactly as
    ///      re-proposing does in the rules and rollback flows; the new
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
