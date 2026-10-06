// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Test-only SP1 verifier stand-in (NEVER DEPLOY)
/// @notice Accepts exactly one program key, and only proofs spelling "valid". Lets the
///         real PiNSAnchor - not the mock - show which verifier and key a batch was
///         checked against, before and after a rules change.
contract ExpectingVerifier {
    bytes32 public immutable expectedVkey;

    constructor(bytes32 _expectedVkey) {
        expectedVkey = _expectedVkey;
    }

    function verifyProof(bytes32 programVKey, bytes calldata, bytes calldata proofBytes) external view {
        require(programVKey == expectedVkey, "wrong program key");
        require(keccak256(proofBytes) == keccak256("valid"), "invalid proof");
    }
}

/// @title Test-only verifier that accepts anything (NEVER DEPLOY)
/// @notice What a hostile rules change would install.
contract AcceptAllVerifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}
