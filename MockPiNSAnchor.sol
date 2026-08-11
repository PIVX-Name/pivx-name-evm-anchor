// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "./PiNSAnchor.sol";

/// @title Mock PiNS Layer-2 Anchor (TESTING ONLY)
/// @notice Inherits PiNSAnchor and overrides proof verification for SP1_PROVER=mock testing
contract MockPiNSAnchor is PiNSAnchor {
    constructor(
        address _sp1Verifier,
        bytes32 _programVkey,
        bytes32 _genesisRoot,
        uint32 _genesisBlockHeight,
        address _sequencer
    ) PiNSAnchor(_sp1Verifier, _programVkey, _genesisRoot, _genesisBlockHeight, _sequencer) {}

    /// @dev Overrides SP1 verification call to bypass cryptographic ZK-SNARK verification during mock tests.
    ///      `view`, matching the base hook — the point of that hook being `view` is that no
    ///      override can re-enter, so the mock must not be the exception that reintroduces
    ///      it. That rules out the MockProofBypassed event this used to emit; RootUpdated
    ///      already records every accepted batch, and no test asserted on the mock event.
    function _verifyProof(bytes calldata publicValues, bytes calldata /* proofBytes */) internal view override {
        // MOCK BYPASS: Cryptographic Verification Skipped for local/CI test pipelines.
        // The payload shape is still checked, so a malformed batch fails here as it would
        // against the real verifier rather than sailing through the mock.
        if (publicValues.length != 96) revert InvalidPublicValues();
    }
}
