// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {BaseAccount, PackedUserOperation} from "account-abstraction/contracts/core/BaseAccount.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";

contract ZKNOX_ERC4337_account is BaseAccount {
    IEntryPoint private _entryPoint;
    bytes private preQuantumPubKey;
    bytes private postQuantumPubKey;
    address private preQuantumLogicContractAddress;
    address private postQuantumLogicContractAddress;

    constructor(
        IEntryPoint _entryPoint0,
        bytes memory _preQuantumPubKey,
        bytes memory _postQuantumPubKey,
        address _preQuantumLogicContractAddress,
        address _postQuantumLogicContractAddress
    ) {
        _entryPoint = _entryPoint0;
        // prequantum logic and key
        preQuantumLogicContractAddress = _preQuantumLogicContractAddress;
        preQuantumPubKey = ISigVerifier(preQuantumLogicContractAddress).setKey(_preQuantumPubKey);
        // postquantum logic and key
        postQuantumLogicContractAddress = _postQuantumLogicContractAddress;
        postQuantumPubKey = ISigVerifier(postQuantumLogicContractAddress).setKey(_postQuantumPubKey);
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        (bytes memory preQuantumSig, bytes memory postQuantumSig) = abi.decode(userOp.signature, (bytes, bytes));

        // Verify pre-quantum signature
        ISigVerifier preQuantumCore = ISigVerifier(preQuantumLogicContractAddress);
        if (preQuantumCore.verify(preQuantumPubKey, userOpHash, preQuantumSig) != preQuantumCore.verify.selector) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify post-quantum signature
        ISigVerifier postQuantumCore = ISigVerifier(postQuantumLogicContractAddress);
        if (postQuantumCore.verify(postQuantumPubKey, userOpHash, postQuantumSig) != postQuantumCore.verify.selector) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    receive() external payable {}
    fallback() external payable {}
}
