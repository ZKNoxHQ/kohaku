// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// lib/account-abstraction/contracts/utils/Exec.sol

// solhint-disable no-inline-assembly

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 */
library Exec {

    function call(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly ("memory-safe") {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function staticcall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal view returns (bool success) {
        assembly ("memory-safe") {
            success := staticcall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function delegateCall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly ("memory-safe") {
            success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    // get returned data from last call or delegateCall
    // maxLen - maximum length of data to return, or zero, for the full length
    function getReturnData(uint256 maxLen) internal pure returns (bytes memory returnData) {
        assembly ("memory-safe") {
            let len := returndatasize()
            if gt(maxLen,0) {
                if gt(len, maxLen) {
                    len := maxLen
                }
            }
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    // revert with explicit byte array (probably reverted info from call)
    function revertWithData(bytes memory returnData) internal pure {
        assembly ("memory-safe") {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    // Propagate revert data from last call
    function revertWithReturnData() internal pure {
        revertWithData(getReturnData(0));
    }
}

// lib/account-abstraction/contracts/interfaces/INonceManager.sol

interface INonceManager {

    /**
     * Return the next nonce for this sender.
     * Within a given key, the nonce values are sequenced (starting with zero, and incremented by one on each userop)
     * But UserOp with different keys can come with arbitrary order.
     *
     * @param sender the account address
     * @param key the high 192 bit of the nonce
     * @return nonce a full nonce to pass for next UserOp with this sender.
     */
    function getNonce(address sender, uint192 key)
    external view returns (uint256 nonce);

    /**
     * Manually increment the nonce of the sender.
     * This method is exposed just for completeness.
     * Account does NOT need to call it, neither during validation, nor elsewhere,
     * as the EntryPoint will update the nonce regardless.
     * Possible use-case is call it with various keys to "initialize" their nonces to one, so that future
     * UserOperations will not pay extra for the first transaction with a given key.
     *
     * @param key - the "nonce key" to increment the "nonce sequence" for.
     */
    function incrementNonce(uint192 key) external;
}

// lib/account-abstraction/contracts/interfaces/ISenderCreator.sol

interface ISenderCreator {
    /**
     * @dev Creates a new sender contract.
     * @return sender Address of the newly created sender contract.
     */
    function createSender(bytes calldata initCode) external returns (address sender);

    /**
     * Use initCallData to initialize an EIP-7702 account.
     * The caller is the EntryPoint contract and it is already verified to be an EIP-7702 account.
     * Note: Can be called multiple times as long as an appropriate initCode is supplied
     *
     * @param sender - the 'sender' EIP-7702 account to be initialized.
     * @param initCallData - the call data to be passed to the sender account call.
     */
    function initEip7702Sender(address sender, bytes calldata initCallData) external;
}

// lib/account-abstraction/contracts/interfaces/IStakeManager.sol

/**
 * Manage deposits and stakes.
 * Deposit is just a balance used to pay for UserOperations (either by a paymaster or an account).
 * Stake is value locked for at least "unstakeDelay" by the staked entity.
 */
interface IStakeManager {
    error InvalidUnstakeDelay(uint256 newUnstakeDelaySec, uint256 currentUnstakeDelaySec);
    error InvalidStake(uint256 msgValue, uint256 currentStake);
    error NotStaked(uint256 currentStake, uint256 unstakeDelaySec, bool staked);
    error InsufficientDeposit(uint256 currentDeposit, uint256 withdrawAmount);
    error StakeNotUnlocked(uint256 withdrawTime, uint256 blockTimestamp);
    error WithdrawalNotDue(uint256 withdrawTime, uint256 blockTimestamp);
    error StakeWithdrawalFailed(address account, address withdrawAddress, uint256 amount, bytes revertReason);
    error DepositWithdrawalFailed(address account, address withdrawAddress, uint256 amount, bytes revertReason);

    event Deposited(address indexed account, uint256 totalDeposit);

    event Withdrawn(
        address indexed account,
        address withdrawAddress,
        uint256 amount
    );

    // Emitted when stake or unstake delay are modified.
    event StakeLocked(
        address indexed account,
        uint256 totalStaked,
        uint256 unstakeDelaySec
    );

    // Emitted once a stake is scheduled for withdrawal.
    event StakeUnlocked(address indexed account, uint256 withdrawTime);

    event StakeWithdrawn(
        address indexed account,
        address withdrawAddress,
        uint256 amount
    );

    /**
     * @param deposit         - The entity's deposit.
     * @param staked          - True if this entity is staked.
     * @param stake           - Actual amount of ether staked for this entity.
     * @param unstakeDelaySec - Minimum delay to withdraw the stake.
     * @param withdrawTime    - First block timestamp where 'withdrawStake' will be callable, or zero if already locked.
     * @dev Sizes were chosen so that deposit fits into one cell (used during handleOp)
     *      and the rest fit into a 2nd cell (used during stake/unstake)
     *      - 112 bit allows for 10^15 eth
     *      - 48 bit for full timestamp
     *      - 32 bit allows 150 years for unstake delay
     */
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    // API struct used by getStakeInfo and simulateValidation.
    struct StakeInfo {
        uint256 stake;
        uint256 unstakeDelaySec;
    }

    /**
     * Get deposit info.
     * @param account - The account to query.
     * @return info   - Full deposit information of given account.
     */
    function getDepositInfo(
        address account
    ) external view returns (DepositInfo memory info);

    /**
     * Get account balance.
     * @param account - The account to query.
     * @return        - The deposit (for gas payment) of the account.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * Add to the deposit of the given account.
     * @param account - The account to add to.
     */
    function depositTo(address account) external payable;

    /**
     * Add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param unstakeDelaySec - The new lock duration before the deposit can be withdrawn.
     */
    function addStake(uint32 unstakeDelaySec) external payable;

    /**
     * Attempt to unlock the stake.
     * The value can be withdrawn (using withdrawStake) after the unstake delay.
     */
    function unlockStake() external;

    /**
     * Withdraw from the (unlocked) stake.
     * Must first call unlockStake and wait for the unstakeDelay to pass.
     * @param withdrawAddress - The address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external;

    /**
     * Withdraw from the deposit.
     * @param withdrawAddress - The address to send withdrawn value.
     * @param withdrawAmount  - The amount to withdraw.
     */
    function withdrawTo(
        address payable withdrawAddress,
        uint256 withdrawAmount
    ) external;
}

// lib/InterfaceVerifier/src/IVerifier.sol

// ZKNox contract

/**
 * @dev Signature verifier interface.
 */
interface ISigVerifier {

    function setKey(bytes calldata key) external returns (bytes memory);

    /**
     * @dev Verifies `signature` as a valid signature of `hash` by `key`.
     *
     * MUST return the bytes4 magic value IERC7913SignatureVerifier.verify.selector if the signature is valid.
     * SHOULD return 0xffffffff or revert if the signature is not valid.
     * SHOULD return 0xffffffff or revert if the key is empty
     */
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

// lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol

/**
 * User Operation struct
 * @param sender                - The sender account of this request.
 * @param nonce                 - Unique value the sender uses to verify it is not a replay.
 * @param initCode              - If set, the account contract will be created by this constructor
 * @param callData              - The method call to execute on this account.
 * @param accountGasLimits      - Packed gas limits for validateUserOp and gas limit passed to the callData method call.
 * @param preVerificationGas    - Gas not calculated by the handleOps method, but added to the gas paid.
 *                                Covers batch overhead.
 * @param gasFees               - packed gas fields maxPriorityFeePerGas and maxFeePerGas - Same as EIP-1559 gas parameters.
 * @param paymasterAndData      - If set, this field holds the paymaster address, verification gas limit, postOp gas limit and paymaster-specific extra data
 *                                The paymaster will pay for the transaction instead of the sender.
 * @param signature             - Sender-verified signature over the entire request, the EntryPoint address and the chain ID.
 *
 *
 * Field layout (enforced on-chain by EntryPoint):
 * - sender: must already be deployed, or be the address that `initCode` will deploy; for EIP-7702 onboarding, `initCode = 0x7702 || optionalPayload`
 *   and `sender.code` must begin `0xef0100 || delegate`.
 * - nonce = uint192(key) || uint64(sequence); EntryPoint tracks sequential values of `sequence` separately for each `key` value.
 * - initCode:
 *     * non-7702: `initCode = factory(20) || factoryCalldata`; the factory must return `sender` and deploy code.
 *     * The `initCode` will be ignored if the `sender` is already deployed.
 *     * 7702: `0x7702` (magic prefix), optionally padded to 20 bytes and followed by the actual `initializationCode` data. This optional payload is executed on `sender` to finalise delegate setup.
 * - callData: executed verbatim; if it starts with `IAccountExecute.executeUserOp.selector` (0x8dd7712f), EntryPoint wraps and forwards `(userOp, userOpHash)`.
 * - accountGasLimits =`uint128(verificationGasLimit) || uint128(callGasLimit)`
 * - gasFees = `uint128(maxPriorityFeePerGas) || uint128(maxFeePerGas)`
 * - paymasterAndData (if non-empty) = `paymaster(20) || verificationGasLimit(16) || postOpGasLimit(16) || paymasterData`
 *     * an optional paymasterSignature may be added by appending:
 *       `paymasterSignature || uint16(paymasterSignature.length) || PAYMASTER_SIG_MAGIC (0x22e325a297439656)`
 * - signature: Used by the account to validate the UserOperation against the `userOpHash`.
 *              The hash covers all UserOperation fields, except `signature` and `paymasterSignature`
 */
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

// lib/account-abstraction/contracts/interfaces/IAccount.sol

interface IAccount {
    /**
     * Validate user's signature and nonce
     * the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert to signal failure.
     *
     * @dev Must validate caller is the entryPoint.
     *      Must validate the signature and nonce
     * @param userOp              - The operation that is about to be executed.
     * @param userOpHash          - Hash of the user's request data. can be used as the basis for signature.
     * @param missingAccountFunds - Missing funds on the account's deposit in the entrypoint.
     *                              This is the minimum amount to transfer to the sender(entryPoint) to be
     *                              able to make the call. The excess is left as a deposit in the entrypoint
     *                              for future calls. Can be withdrawn anytime using "entryPoint.withdrawTo()".
     *                              In case there is a paymaster in the request (or the current deposit is high
     *                              enough), this value will be zero.
     * @return validationData       - Packaged ValidationData structure. use `_packValidationData` and
     *                              `_unpackValidationData` to encode and decode.
     *                              <20-byte> aggregatorOrSigFail - 0 for valid signature, 1 to mark signature failure,
     *                                 otherwise, an address of an "aggregator" contract.
     *                              <6-byte> validUntil - Last timestamp this operation is valid at, or 0 for "indefinitely"
     *                              <6-byte> validAfter - First timestamp this operation is valid
     *                                                    If an account doesn't use time-range, it is enough to
     *                                                    return SIG_VALIDATION_FAILED value (1) for signature failure.
     *                              Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

// lib/account-abstraction/contracts/interfaces/IAggregator.sol

/**
 * Aggregated Signatures validator.
 */
interface IAggregator {
    /**
     * Validate an aggregated signature.
     * Reverts if the aggregated signature does not match the given list of operations.
     * @param userOps   - An array of UserOperations to validate the signature for.
     * @param signature - The aggregated signature.
     */
    function validateSignatures(
        PackedUserOperation[] calldata userOps,
        bytes calldata signature
    ) external;

    /**
     * Validate the signature of a single userOp.
     * This method should be called by bundler after EntryPointSimulation.simulateValidation() returns
     * the aggregator this account uses.
     * First it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
     * @param userOp        - The userOperation received from the user.
     * @return sigForUserOp - The value to put into the signature field of the userOp when calling handleOps.
     *                        (usually empty, unless account and aggregator support some kind of "multisig".
     */
    function validateUserOpSignature(
        PackedUserOperation calldata userOp
    ) external view returns (bytes memory sigForUserOp);

    /**
     * Aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code to perform this aggregation.
     * @param userOps              - An array of UserOperations to collect the signatures from.
     * @return aggregatedSignature - The aggregated signature.
     */
    function aggregateSignatures(
        PackedUserOperation[] calldata userOps
    ) external view returns (bytes memory aggregatedSignature);
}

// lib/account-abstraction/contracts/core/Helpers.sol

/* solhint-disable no-inline-assembly */

using UserOperationLib for bytes;

 /*
  * For simulation purposes, validateUserOp (and validatePaymasterUserOp)
  * must return this value in case of signature failure, instead of revert.
  */
uint256 constant SIG_VALIDATION_FAILED = 1;

/*
 * For simulation purposes, validateUserOp (and validatePaymasterUserOp)
 * return this value on success.
 */
uint256 constant SIG_VALIDATION_SUCCESS = 0;

/**
 * Returned data from validateUserOp.
 * validateUserOp returns a uint256, which is created by `_packedValidationData` and
 * parsed by `_parseValidationData`.
 * @param aggregator  - address(0) - The account validated the signature by itself.
 *                      address(1) - The account failed to validate the signature.
 *                      otherwise - This is an address of a signature aggregator that must
 *                                  be used to validate the signature.
 * @param validAfter  - This UserOp is valid only after this timestamp.
 * @param validUntil - Last timestamp this operation is valid at, or 0 for "indefinitely".
 */
struct ValidationData {
    address aggregator;
    uint48 validAfter;
    uint48 validUntil;
}

/**
 * Extract aggregator/sigFailed, validAfter, validUntil.
 * Also convert zero validUntil to type(uint48).max.
 * @param validationData - The packed validation data.
 * @return data - The unpacked in-memory validation data.
 */
function _parseValidationData(
    uint256 validationData
) pure returns (ValidationData memory data) {
    address aggregator = address(uint160(validationData));
    uint48 validUntil = uint48(validationData >> 160);
    if (validUntil == 0) {
        validUntil = type(uint48).max;
    }
    uint48 validAfter = uint48(validationData >> (48 + 160));
    return ValidationData(aggregator, validAfter, validUntil);
}

/**
 * Helper to pack the return value for validateUserOp.
 * @param data - The ValidationData to pack.
 * @return the packed validation data.
 */
function _packValidationData_0(
    ValidationData memory data
) pure returns (uint256) {
    return
        uint160(data.aggregator) |
        (uint256(data.validUntil) << 160) |
        (uint256(data.validAfter) << (160 + 48));
}

/**
 * Helper to pack the return value for validateUserOp, when not using an aggregator.
 * @param sigFailed  - True for signature failure, false for success.
 * @param validUntil - Last timestamp this operation is valid at, or 0 for "indefinitely".
 * @param validAfter - First timestamp this UserOperation is valid.
 * @return the packed validation data.
 */
function _packValidationData_1(
    bool sigFailed,
    uint48 validUntil,
    uint48 validAfter
) pure returns (uint256) {
    return
        (sigFailed ?  SIG_VALIDATION_FAILED : SIG_VALIDATION_SUCCESS) |
        (uint256(validUntil) << 160) |
        (uint256(validAfter) << (160 + 48));
}

/**
 * keccak function over calldata.
 * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting solidity do it.
 *
 * @param data - the calldata bytes array to perform keccak on.
 * @return ret - the keccak hash of the 'data' array.
 */
function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly ("memory-safe") {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}

/**
 * @notice Computes the Keccak-256 hash of a slice of calldata, followed by an 8-byte suffix.
 * This function copies the first `len` bytes from the given calldata array `data` into memory.
 * The assembly code is equivalent to:
 *      keccak256(abi.encodePacked(data[0:len], suffix))
 * But more efficient, and doesn't move the free memory pointer, allowing the memory to be reused later.
 *
 * @param data   Calldata byte array to read from.
 * @param len    Number of bytes to copy from `data` starting at its offset.
 * @param suffix 8-byte value appended to the data bytes before hashing.
 *
 * @return ret The hash of (data[0:len] || suffix).
 */
function calldataKeccakWithSuffix(bytes calldata data, uint256 len, bytes8 suffix) pure returns (bytes32 ret) {
    assembly ("memory-safe") {
        let mem := mload(0x40)
        calldatacopy(mem, data.offset, len)
        mstore(add(mem, len), suffix)
        len := add(len, 8)
        ret := keccak256(mem, len)
    }
}

/**
 * Keccak function over paymaster data.
 * If data ends with `PAYMASTER_SIG_MAGIC`, then
 * read the previous 2 bytes as pmSignatureLength,
 * and ignore this suffix from the hash.
 * This means that the trailing pmSignatureLength+10 bytes are not covered by the UserOpHash, and thus are not signed.
 * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting solidity do it.
 *
 * @param data - the calldata bytes array to perform keccak on.
 * @return ret - the keccak hash of the 'data' array.
 */
function paymasterDataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    uint256 pmSignatureLength = data.getPaymasterSignatureLength();
    if (pmSignatureLength > 0) {
        unchecked {
            //keccak everything up to the paymasterSignature, but still append the sig magic.
            return calldataKeccakWithSuffix(data, data.length - (pmSignatureLength + UserOperationLib.PAYMASTER_SUFFIX_LEN), UserOperationLib.PAYMASTER_SIG_MAGIC);
        }
    }
    return calldataKeccak(data);
}

/**
 * The minimum of two numbers.
 * @param a - First number.
 * @param b - Second number.
 * @return - the minimum value.
 */
    function min(uint256 a, uint256 b) pure returns (uint256) {
        return a < b ? a : b;
    }

/**
 * standard solidity memory allocation finalization.
 * copied from solidity generated code
 * @param memPointer - The current memory pointer
 * @param allocationSize - Bytes allocated from memPointer.
 */
    function finalizeAllocation(uint256 memPointer, uint256 allocationSize) pure {

        assembly ("memory-safe"){
            finalize_allocation(memPointer, allocationSize)

            function finalize_allocation(memPtr, size) {
                let newFreePtr := add(memPtr, round_up_to_mul_of_32(size))
                mstore(64, newFreePtr)
            }

            function round_up_to_mul_of_32(value) -> result {
                result := and(add(value, 31), not(31))
            }
        }
    }

// lib/account-abstraction/contracts/core/UserOperationLib.sol

/* solhint-disable no-inline-assembly */

/**
 * Utility functions helpful when working with UserOperation structs.
 */
library UserOperationLib {

    error InvalidPaymasterSignatureLength(uint256 dataLength, uint256 pmSignatureLength);

    uint256 public constant PAYMASTER_VALIDATION_GAS_OFFSET = 20;
    uint256 public constant PAYMASTER_POSTOP_GAS_OFFSET = 36;
    uint256 public constant PAYMASTER_DATA_OFFSET = 52;

    uint256 constant internal PAYMASTER_SIG_MAGIC_LEN = 8;
    uint256 constant internal PAYMASTER_SUFFIX_LEN = PAYMASTER_SIG_MAGIC_LEN + 2; // suffix length (signature length + magic)
    bytes8 constant internal  PAYMASTER_SIG_MAGIC = 0x22e325a297439656; // keccak("PaymasterSignature")[:8]
    uint256 constant internal MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN = PAYMASTER_DATA_OFFSET + PAYMASTER_SUFFIX_LEN; // minimum length of paymasterData that can contain a paymaster signature.

    /**
     * Relayer/block builder might submit the TX with higher priorityFee,
     * but the user should not pay above what he signed for.
     * @param userOp - The user operation data.
     */
    function gasPrice(
        PackedUserOperation calldata userOp
    ) internal view returns (uint256) {
        unchecked {
            (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = unpackUints(userOp.gasFees);
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    bytes32 internal constant PACKED_USEROP_TYPEHASH =
    // solhint-disable-next-line gas-small-strings
    keccak256(
        "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"
    );

    /**
     * Pack the user operation data into bytes for hashing.
     * @param userOp - The user operation data.
     * @param overrideInitCodeHash - If set, encode this instead of the initCode field in the userOp.
     */
    function encode(
        PackedUserOperation calldata userOp,
        bytes32 overrideInitCodeHash
    ) internal pure returns (bytes memory ret) {
        address sender = userOp.sender;
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = overrideInitCodeHash != 0 ? overrideInitCodeHash : calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        bytes32 hashPaymasterAndData = paymasterDataKeccak(userOp.paymasterAndData);

        return abi.encode(
            UserOperationLib.PACKED_USEROP_TYPEHASH,
            sender, nonce,
            hashInitCode, hashCallData,
            accountGasLimits, preVerificationGas, gasFees,
            hashPaymasterAndData
        );
    }

    function unpackUints(
        bytes32 packed
    ) internal pure returns (uint256 high128, uint256 low128) {
        return (unpackHigh128(packed), unpackLow128(packed));
    }

    // Unpack just the high 128-bits from a packed value
    function unpackHigh128(bytes32 packed) internal pure returns (uint256) {
        return uint256(packed) >> 128;
    }

    // Unpack just the low 128-bits from a packed value
    function unpackLow128(bytes32 packed) internal pure returns (uint256) {
        return uint128(uint256(packed));
    }

    function unpackMaxPriorityFeePerGas(PackedUserOperation calldata userOp)
    internal pure returns (uint256) {
        return unpackHigh128(userOp.gasFees);
    }

    function unpackMaxFeePerGas(PackedUserOperation calldata userOp)
    internal pure returns (uint256) {
        return unpackLow128(userOp.gasFees);
    }

    function unpackVerificationGasLimit(PackedUserOperation calldata userOp)
    internal pure returns (uint256) {
        return unpackHigh128(userOp.accountGasLimits);
    }

    function unpackCallGasLimit(PackedUserOperation calldata userOp)
    internal pure returns (uint256) {
        return unpackLow128(userOp.accountGasLimits);
    }

    function unpackPaymasterVerificationGasLimit(PackedUserOperation calldata userOp)
    internal pure returns (uint256) {
        return uint128(bytes16(userOp.paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET : PAYMASTER_POSTOP_GAS_OFFSET]));
    }

    function unpackPostOpGasLimit(PackedUserOperation calldata userOp)
    internal pure returns (uint256) {
        return uint128(bytes16(userOp.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET : PAYMASTER_DATA_OFFSET]));
    }

    function unpackPaymasterStaticFields(
        bytes calldata paymasterAndData
    ) internal pure returns (address paymaster, uint256 validationGasLimit, uint256 postOpGasLimit) {
        return (
            address(bytes20(paymasterAndData[: PAYMASTER_VALIDATION_GAS_OFFSET])),
            uint128(bytes16(paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET : PAYMASTER_POSTOP_GAS_OFFSET])),
            uint128(bytes16(paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET : PAYMASTER_DATA_OFFSET]))
        );
    }

    /**
     * return the length of the paymaster signature appended in paymasterAndData.
     * return 0 if no signature.
     * note that this signature is not part of the userOpHash, and thus not signed by the user.
     */
    function getPaymasterSignatureLength(
        bytes calldata paymasterAndData
    ) internal pure returns (uint256 paymasterSignatureLength) {
        unchecked {
            uint256 dataLength = paymasterAndData.length;
            if (dataLength < MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN) {
                return 0;
            }
            bytes8 suffix8 = bytes8(paymasterAndData[dataLength - PAYMASTER_SIG_MAGIC_LEN : dataLength]);
            if (suffix8 != PAYMASTER_SIG_MAGIC) {
                return 0;
            }
            uint256 pmSignatureLength = uint16(bytes2(paymasterAndData[dataLength - PAYMASTER_SUFFIX_LEN :]));

            if (pmSignatureLength > dataLength - MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN) {
                // paymasterSignature cannot extend before the paymasterData
                revert InvalidPaymasterSignatureLength(dataLength, pmSignatureLength);
            }
            return pmSignatureLength;
        }
    }

    /**
     * return the paymasterData that is signed by the user's signature
     * this data excludes the paymaster signature appended at the end of paymasterAndData
     */
    function getSignedPaymasterData(
        bytes calldata paymasterAndData
    ) internal pure returns (bytes calldata signedPaymasterData) {
        uint256 sigLen = getPaymasterSignatureLength(paymasterAndData);
        uint256 paymasterDataLen = paymasterAndData.length;
        if (sigLen != 0) {
            paymasterDataLen -= (sigLen + PAYMASTER_SUFFIX_LEN);
        }
        return paymasterAndData[PAYMASTER_DATA_OFFSET : paymasterDataLen];
    }

    /**
     * decodes dynamic signature appended to paymasterAndData
     * note that this signature is not part of the userOpHash, and thus not signed by the user.
     * @param paymasterAndData - The paymasterAndData field of the user operation
     * @return pmSig the paymaster-specific signature (may be empty)
     */
    function getPaymasterSignature(bytes calldata paymasterAndData
    ) internal pure returns (bytes calldata pmSig) {
        uint256 len = getPaymasterSignatureLength(paymasterAndData);
        return getPaymasterSignatureWithLength(paymasterAndData, len);
    }

    /**
     * decodes dynamic signature appended to paymasterAndData
     * Assumes the length field is valid, and was obtained from getPaymasterSignatureLength
     * @param paymasterAndData - The paymasterAndData field of the user operation
     * @param paymasterSignatureLength - length of the signature (as returned by getPaymasterSignatureLength)
     * @return pmSig the paymaster-specific signature (may be empty)
     */
    function getPaymasterSignatureWithLength(
        bytes calldata paymasterAndData, uint256 paymasterSignatureLength
    ) internal pure returns (bytes calldata pmSig) {
        if (paymasterSignatureLength == 0) {
            return paymasterAndData[0 : 0];
        }
        uint256 dataLen = paymasterAndData.length;
        unchecked {
            uint256 pmSigEnd = dataLen - PAYMASTER_SUFFIX_LEN;
            uint256 pmSigBegin =  pmSigEnd - paymasterSignatureLength;
            return paymasterAndData[pmSigBegin : pmSigEnd];
        }
    }

    /**
     * encode the paymaster signature as suffix to append to paymasterAndData
     * This method is a reference for off-chain encoding of paymaster signature.
     */
    function encodePaymasterSignature(bytes calldata paymasterSignature) internal pure returns (bytes memory) {
        uint256 len = paymasterSignature.length;
        if (len == 0) {
            return "";
        }

        return abi.encodePacked(
            paymasterSignature,
            uint16(len),
            PAYMASTER_SIG_MAGIC
        );
    }

    /**
     * Hash the user operation data.
     * @param userOp - The user operation data.
     * @param overrideInitCodeHash - If set, the initCode hash will be replaced with this value just for UserOp hashing.
     */
    function hash(
        PackedUserOperation calldata userOp,
        bytes32 overrideInitCodeHash
    ) internal pure returns (bytes32) {
        return keccak256(encode(userOp, overrideInitCodeHash));
    }
}

// lib/account-abstraction/contracts/interfaces/IEntryPoint.sol
/**
 ** Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 ** Only one instance required on each chain.
 **/

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

interface IEntryPoint is IStakeManager, INonceManager {
    /***
     * An event emitted after each successful request.
     * @param userOpHash    - Unique identifier for the request (hash its entire content, except signature).
     * @param sender        - The account that generates this request.
     * @param paymaster     - If non-null, the paymaster that pays for this request.
     * @param nonce         - The nonce value from the request.
     * @param success       - True if the sender transaction succeeded, false if reverted.
     * @param actualGasCost - Actual amount paid (by account or paymaster) for this UserOperation.
     * @param actualGasUsed - Total gas used by this UserOperation (including preVerification, creation,
     *                        validation and execution).
     */
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    /**
     * Account "sender" was deployed.
     * @param userOpHash - The userOp that deployed this account. UserOperationEvent will follow.
     * @param sender     - The account that is deployed
     * @param factory    - The factory used to deploy this account (in the initCode)
     * @param paymaster  - The paymaster used by this UserOp
     */
    event AccountDeployed(
        bytes32 indexed userOpHash,
        address indexed sender,
        address factory,
        address paymaster
    );

    /**
     * Account "sender" already exists and the 'initCode' was ignored.
     * @param userOpHash    - The current userOp. UserOperationEvent will follow.
     * @param sender        - The account that was supposed to be deployed.
     * @param unusedFactory - The factory contract that was not used but was specified in the 'initCode'.
     */
    event IgnoredInitCode(
        bytes32 indexed userOpHash,
        address indexed sender,
        address unusedFactory
    );

    /**
     * Account "sender" is an EIP-7702 account that was initialized during this UserOperation.
     * @param userOpHash    - The current userOp. UserOperationEvent will follow.
     * @param sender        - The account that was supposed to be deployed.
     */
    event EIP7702AccountInitialized(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed delegate
    );

    /**
     * An event emitted if the UserOperation "callData" reverted with non-zero length.
     * @param userOpHash   - The request unique identifier.
     * @param sender       - The sender of this request.
     * @param nonce        - The nonce used in the request.
     * @param revertReason - The return bytes from the reverted "callData" call.
     */
    event UserOperationRevertReason(
        bytes32 indexed userOpHash,
        address indexed sender,
        uint256 nonce,
        bytes revertReason
    );

    /**
     * An event emitted if the UserOperation Paymaster's "postOp" call reverted with non-zero length.
     * @param userOpHash   - The request unique identifier.
     * @param sender       - The sender of this request.
     * @param nonce        - The nonce used in the request.
     * @param revertReason - The return bytes from the reverted call to "postOp".
     */
    event PostOpRevertReason(
        bytes32 indexed userOpHash,
        address indexed sender,
        uint256 nonce,
        bytes revertReason
    );

    /**
     * UserOp consumed more than prefund. The UserOperation is reverted, and no refund is made.
     * @param userOpHash   - The request unique identifier.
     * @param sender       - The sender of this request.
     * @param nonce        - The nonce used in the request.
     */
    event UserOperationPrefundTooLow(
        bytes32 indexed userOpHash,
        address indexed sender,
        uint256 nonce
    );

    /**
     * An event emitted by handleOps() and handleAggregatedOps(), before starting the execution loop.
     * Any event emitted before this event, is part of the validation.
     */
    event BeforeExecution();

    /**
     * Signature aggregator used by the following UserOperationEvents within this bundle.
     * @param aggregator - The aggregator used for the following UserOperationEvents.
     */
    event SignatureAggregatorChanged(address indexed aggregator);

    /**
     * A custom revert error of 'handleOps' and 'handleAggregatedOps', to identify the offending UserOperation.
     * Should be caught in off-chain 'handleOps'/'handleAggregatedOps' simulation and should not happen on-chain.
     *
     * Useful for mitigating DoS attempts against batchers or for troubleshooting of factory/account/paymaster reverts.
     * NOTE: If 'simulateValidation' passes successfully, there should be no reason for 'handleOps' to revert as well.
     *
     * @param opIndex - Index into the array of ops to the failed one.
     *                  When using 'simulateValidation', this value is always zero.
     *
     * @param reason  - Revert reason. The string starts with a unique code "AAmn",
     *                  where "m" is "1" for factory, "2" for account, "3" for paymaster, and "9" for other issues,
     *                  so a failure can be attributed to the correct entity.
     */
    error FailedOp(uint256 opIndex, string reason);

    error InvalidBeneficiary(address beneficiary);
    error FailedSendToBeneficiary(address beneficiary, uint256 amount, bytes revertData);
    error InternalFunction();
    error InvalidPaymasterData(uint256 paymasterAndDataLength);
    error InvalidPaymaster(address paymaster);

    /**
     * A custom revert error of handleOps and handleAggregatedOps, to report a revert by account or paymaster.
     * @param opIndex - Index of the failed UserOperation in the array of ops. In simulateValidation, this value is always zero.
     * @param reason  - Revert reason. See the 'FailedOp(uint256,string)' error above.
     * @param inner   - Revert data caught from the inner revert reason of an entity contract.
     * @dev note that inner is truncated to 2048 bytes
     */
    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    error PostOpReverted(bytes returnData);

    /**
     * Error case when a signature aggregator fails to verify the aggregated signature it had created.
     * @param aggregator The aggregator that failed to verify the signature
     */
    error SignatureValidationFailed(address aggregator);

    // Return value of getSenderAddress.
    error SenderAddressResult(address sender);

    // UserOps handled, per aggregator.
    struct UserOpsPerAggregator {
        PackedUserOperation[] userOps;
        // Aggregator address
        IAggregator aggregator;
        // Aggregated signature
        bytes signature;
    }

    /**
     * Execute a batch of UserOperations.
     * No signature aggregator is used.
     * If any account requires an aggregator (that is, it returned an aggregator when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops         - The operations to execute.
     * @param beneficiary - The address to receive the fees.
     */
    function handleOps(
        PackedUserOperation[] calldata ops,
        address payable beneficiary
    ) external;

    /**
     * Execute a batch of UserOperation with Aggregators
     * @param opsPerAggregator - The operations to execute, grouped by aggregator (or address(0) for no-aggregator accounts).
     * @param beneficiary      - The address to receive the fees.
     */
    function handleAggregatedOps(
        UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    ) external;

    /**
     * Generate a request Id - unique identifier for this request.
     * The request ID is a hash over the content of the userOp (except the signature), entrypoint address, chainId and (optionally) 7702 delegate address
     * @param userOp - The user operation to generate the request ID for.
     * @return hash the hash of this UserOperation
     */
    function getUserOpHash(
        PackedUserOperation calldata userOp
    ) external view returns (bytes32);

    /**
     * Allows the AA-aware contracts to query the hash of the currently running UserOperation.
     * @return hash - the hash of the currently running UserOperation, or 0 if none.
     */
    function getCurrentUserOpHash() external view returns (bytes32);

    /**
     * Gas and return values during simulation.
     * @param preOpGas         - The gas used for validation (including preValidationGas)
     * @param prefund          - The required prefund for this operation
     * @param accountValidationData   - returned validationData from account.
     * @param paymasterValidationData - return validationData from paymaster.
     * @param paymasterContext - Returned by validatePaymasterUserOp (to be passed into postOp)
     */
    struct ReturnInfo {
        uint256 preOpGas;
        uint256 prefund;
        uint256 accountValidationData;
        uint256 paymasterValidationData;
        bytes paymasterContext;
    }

    /**
     * Get counterfactual sender address.
     * Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * This method always revert, and returns the address in SenderAddressResult error.
     * @notice this method cannot be used for EIP-7702 derived contracts.
     *
     * @param initCode - The constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes memory initCode) external;

    error DelegateAndRevert(bool success, bytes ret);

    /**
     * Helper method for dry-run testing.
     * @dev calling this method, the EntryPoint will make a delegatecall to the given data, and report (via revert) the result.
     *  The method always revert, so is only useful off-chain for dry run calls, in cases where state-override to replace
     *  actual EntryPoint code is less convenient.
     * @param target a target contract to make a delegatecall from entrypoint
     * @param data data to pass to target in a delegatecall
     */
    function delegateAndRevert(address target, bytes calldata data) external;

    /**
     * @notice Retrieves the immutable SenderCreator contract which is responsible for deployment of sender contracts.
     */
    function senderCreator() external view returns (ISenderCreator);
}

// lib/account-abstraction/contracts/core/BaseAccount.sol

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-empty-blocks */
/* solhint-disable no-inline-assembly */

/**
 * Basic account implementation.
 * This contract provides the basic logic for implementing the IAccount interface - validateUserOp
 * Specific account implementation should inherit it and provide the account-specific logic.
 */
abstract contract BaseAccount is IAccount {
    using UserOperationLib for PackedUserOperation;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error ExecuteError(uint256 index, bytes error);
    error NotFromEntryPoint(address msgSender, address entity, address entryPoint);

    /**
     * Return the account nonce.
     * This method returns the next sequential nonce.
     * For a nonce of a specific key, use `entrypoint.getNonce(account, key)`
     */
    function getNonce() public view virtual returns (uint256) {
        return entryPoint().getNonce(address(this), 0);
    }

    /**
     * Return the entryPoint used by this account.
     * Subclass should return the current entryPoint used by this account.
     */
    function entryPoint() public view virtual returns (IEntryPoint);

    /**
     * execute a single call from the account.
     */
    function execute(address target, uint256 value, bytes calldata data) virtual external {
        _requireForExecute();

        bool ok = Exec.call(target, value, data, gasleft());
        if (!ok) {
            Exec.revertWithReturnData();
        }
    }

    /**
     * execute a batch of calls.
     * revert on the first call that fails.
     * If the batch reverts, and it contains more than a single call, then wrap the revert with ExecuteError,
     *  to mark the failing call index.
     */
    function executeBatch(Call[] calldata calls) virtual external {
        _requireForExecute();

        uint256 callsLength = calls.length;
        for (uint256 i = 0; i < callsLength; i++) {
            Call calldata call = calls[i];
            bool ok = Exec.call(call.target, call.value, call.data, gasleft());
            if (!ok) {
                if (callsLength == 1) {
                    Exec.revertWithReturnData();
                } else {
                    revert ExecuteError(i, Exec.getReturnData(0));
                }
            }
        }
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256 validationData) {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }

    /**
     * Ensure the request comes from the known entrypoint.
     */
    function _requireFromEntryPoint() internal view virtual {
        require(
            msg.sender == address(entryPoint()),
            NotFromEntryPoint(
                msg.sender,
                address(this),
                address(entryPoint())
            )
        );
    }

    function _requireForExecute() internal view virtual {
        _requireFromEntryPoint();
    }

    /**
     * Validate the signature is valid for this message.
     * @param userOp          - Validate the userOp.signature field.
     * @param userOpHash      - Convenient field: the hash of the request, to check the signature against.
     *                          (also hashes the entrypoint and chain id)
     * @return validationData - Signature and time-range of this operation.
     *                          <20-byte> aggregatorOrSigFail - 0 for valid signature, 1 to mark signature failure,
     *                                    otherwise, an address of an aggregator contract.
     *                          <6-byte> validUntil - Last timestamp this operation is valid at, or 0 for "indefinitely"
     *                          <6-byte> validAfter - first timestamp this operation is valid
     *                          If the account doesn't use time-range, it is enough to return
     *                          SIG_VALIDATION_FAILED value (1) for signature failure.
     *                          Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256 validationData);

    /**
     * Validate the nonce of the UserOperation.
     * This method may validate the nonce requirement of this account.
     * e.g.
     * To limit the nonce to use sequenced UserOps only (no "out of order" UserOps):
     *      `require(nonce < type(uint64).max)`
     * For a hypothetical account that *requires* the nonce to be out-of-order:
     *      `require(nonce & type(uint64).max == 0)`
     *
     * The actual nonce uniqueness is managed by the EntryPoint, and thus no other
     * action is needed by the account itself.
     *
     * @param nonce to validate
     *
     * solhint-disable-next-line no-empty-blocks
     */
    function _validateNonce(uint256 nonce) internal view virtual {
    }

    /**
     * Sends to the entrypoint (msg.sender) the missing funds for this transaction.
     * SubClass MAY override this method for better funds management
     * (e.g. send to the entryPoint more than the minimum required, so that in future transactions
     * it will not be required to send again).
     * @param missingAccountFunds - The minimum value this method should send the entrypoint.
     *                              This value MAY be zero, in case there is enough deposit,
     *                              or the userOp has a paymaster.
     */
    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{
                    value: missingAccountFunds
                }("");
            (success);
            // Ignore failure (its EntryPoint's job to verify, not account.)
        }
    }
}

// src/ZKNOX_ERC4337_account.sol

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

    /// @notice Verify hybrid signature (pre- and post-quantum)
    /// @param preQPubKey is a pre-quantum public key
    /// @param postQPubKey is a post-quantum public key
    /// @param preQLogicContractAddress the logic of the pre-quantum verification
    /// @param postQLogicContractAddress the logic of the post-quantum verification
    /// @param digest The data that was signed
    /// @param preQuantumSig the pre-quantum signature: [r, s, v] for k1, [r, s] for r1
    /// @param postQuantumSig the post-quantum signature (depending on the scheme)
    /// @return true if both signatures are valid
    function isValid(
        bytes memory preQPubKey,
        bytes memory postQPubKey,
        address preQLogicContractAddress,
        address postQLogicContractAddress,
        bytes32 digest,
        bytes memory preQuantumSig,
        bytes memory postQuantumSig
    ) public view returns (bool) {
        // Validate digest length
        if (digest.length > 32) {
            return false;
        }

        // Verify pre-quantum signature
        ISigVerifier preQuantumCore = ISigVerifier(preQLogicContractAddress);
        if (preQuantumCore.verify(preQPubKey, digest, preQuantumSig) != preQuantumCore.verify.selector) {
            return false;
        }

        // Verify post-quantum signature
        ISigVerifier postQuantumCore = ISigVerifier(postQLogicContractAddress);
        if (postQuantumCore.verify(postQPubKey, digest, postQuantumSig) != postQuantumCore.verify.selector) {
            return false;
        }
        return true;
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        (bytes memory preQuantumSig, bytes memory postQuantumSig) = abi.decode(userOp.signature, (bytes, bytes));
        bool result = isValid(
            preQuantumPubKey,
            postQuantumPubKey,
            preQuantumLogicContractAddress,
            postQuantumLogicContractAddress,
            userOpHash,
            preQuantumSig,
            postQuantumSig
        );
        if (!result) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    receive() external payable {}
    fallback() external payable {}
}

