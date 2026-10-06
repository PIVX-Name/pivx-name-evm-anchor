// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "./PiNSAnchor.sol";

/// @title Mock PiNS Layer-2 Anchor (TESTING ONLY)
/// @notice Inherits PiNSAnchor and overrides proof verification for SP1_PROVER=mock testing
contract MockPiNSAnchor is PiNSAnchor {
    error NotATestChain(uint256 chainId);

    /// @dev Refuses to deploy anywhere but a local chain or BSC testnet. This contract
    ///      accepts any batch, and its artifacts sit beside the real ones; a warning in the
    ///      docs is the only other thing between it and a mainnet deployment with every
    ///      cryptographic check disabled. Add a testnet's chain id here deliberately.
    constructor(
        address _sp1Verifier,
        bytes32 _programVkey,
        uint32 _genesisBlockHeight,
        address _sequencer,
        uint64 _rulesTimelock
    ) PiNSAnchor(_sp1Verifier, _programVkey, _genesisBlockHeight, _sequencer, _rulesTimelock) {
        if (
            block.chainid != 1337 && // ganache, used by the test suite
            block.chainid != 31337 && // hardhat / anvil
            block.chainid != 97 // BSC testnet
        ) revert NotATestChain(block.chainid);
    }

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
