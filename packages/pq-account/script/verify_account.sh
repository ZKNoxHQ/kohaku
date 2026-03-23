#!/bin/bash

# Verify an already-deployed ERC4337 account on Etherscan.
#
# Usage:
#   ./script/verify_account.sh <account_address> <etherscan_api_key> <tx_hash>
#
# Example:
#   ./script/verify_account.sh 0x62E7795396bD7CB1DA898D2B000ECd81f686Ff7b YOUR_API_KEY 0xbc1bd20d...

ACCOUNT_ADDRESS=$1
API_KEY=$2
TX_HASH=$3

RPC="wss://ethereum-sepolia-rpc.publicnode.com"

if [ -z "$ACCOUNT_ADDRESS" ] || [ -z "$API_KEY" ] || [ -z "$TX_HASH" ]; then
    echo "Usage: $0 <account_address> <etherscan_api_key> <tx_hash>"
    exit 1
fi

echo "Extracting constructor args from tx $TX_HASH..."

# Get the factory calldata (preQuantumPubKey, postQuantumPubKey)
CALLDATA=$(cast tx $TX_HASH input --rpc-url $RPC)

# Decode createAccount(bytes,bytes) — skip 4-byte selector
ARGS=$(cast calldata-decode "createAccount(bytes,bytes)" $CALLDATA)

# Extract the two bytes arguments
PRE_QUANTUM_PUBKEY=$(echo "$ARGS" | sed -n '1p')
POST_QUANTUM_PUBKEY=$(echo "$ARGS" | sed -n '2p')

echo "Pre-quantum pubkey (ECDSA address): $PRE_QUANTUM_PUBKEY"
# The postQuantumPubKey is ABI-encoded: 32B offset + 32B length + data
# Decode to show the actual uint256[] contents
echo "Post-quantum pubkey (ABI-encoded, $(echo -n $POST_QUANTUM_PUBKEY | wc -c) hex chars = $(( ($(echo -n $POST_QUANTUM_PUBKEY | wc -c) - 2) / 2 )) bytes)"

# Read factory address from tx
FACTORY=$(cast tx $TX_HASH to --rpc-url $RPC)
echo "Factory: $FACTORY"

# Read immutables from factory
ENTRY_POINT=$(cast call $FACTORY "ENTRY_POINT()(address)" --rpc-url $RPC)
PRE_QUANTUM_LOGIC=$(cast call $FACTORY "PRE_QUANTUM_LOGIC()(address)" --rpc-url $RPC)
POST_QUANTUM_LOGIC=$(cast call $FACTORY "POST_QUANTUM_LOGIC()(address)" --rpc-url $RPC)

echo "EntryPoint: $ENTRY_POINT"
echo "PreQuantumLogic: $PRE_QUANTUM_LOGIC"
echo "PostQuantumLogic: $POST_QUANTUM_LOGIC"

# Encode constructor args
CONSTRUCTOR_ARGS=$(cast abi-encode \
    "constructor(address,bytes,bytes,address,address)" \
    $ENTRY_POINT \
    $PRE_QUANTUM_PUBKEY \
    $POST_QUANTUM_PUBKEY \
    $PRE_QUANTUM_LOGIC \
    $POST_QUANTUM_LOGIC)

echo ""
echo "Verifying $ACCOUNT_ADDRESS..."

forge verify-contract \
    --chain sepolia \
    --constructor-args $CONSTRUCTOR_ARGS \
    --etherscan-api-key $API_KEY \
    $ACCOUNT_ADDRESS \
    src/ZKNOX_ERC4337_account.sol:ZKNOX_ERC4337_account
