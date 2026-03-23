import { ethers } from 'ethers';
import { redirectConsole } from './utils.js';
import { deriveSeeds } from './pqslip.js';
import { signHybridUserOp, setTransportMode } from './hardware-signer/ledgerTransport.js';

import {
    createBaseUserOperation,
    signUserOpHybrid,
    estimateUserOperationGas,
    updateUserOpWithGasEstimates,
    submitUserOperation,
    ENTRY_POINT_ADDRESS
} from './userOperation.js';

import * as softMldsa  from './software-signer/mldsaSigner.js';
import * as softFalcon from './software-signer/falconSigner.js';
import * as softEcdsa  from './software-signer/ecdsaSigner.js';
import * as hwMldsa    from './hardware-signer/mldsaSigner.js';
import * as hwEcdsa    from './hardware-signer/ecdsaSigner.js';

/**
 * Return the correct { pq, ecdsa } signer pair.
 */
function getSigners(mode, pqAlgo) {
    if (mode === 'ledger') return { pq: hwMldsa, ecdsa: hwEcdsa };
    return {
        pq:    pqAlgo === 'falcon' ? softFalcon : softMldsa,
        ecdsa: softEcdsa,
    };
}

/**
 * Dummy PQ signature length for gas estimation.
 * ML-DSA-44 = 2420 B, Falcon-512 ≈ 1064 B.
 */
function pqDummySigLen(pqAlgo) {
    return pqAlgo === 'falcon' ? 1064 : 2420;
}

/**
 * Build a dummy hybrid signature for gas estimation.
 */
export function getDummySignature(pqAlgo = 'mldsa') {
    const abi = ethers.AbiCoder.defaultAbiCoder();
    const dummyEcdsa = ethers.hexlify(new Uint8Array(65).fill(0xff));
    const dummyPq    = ethers.hexlify(new Uint8Array(pqDummySigLen(pqAlgo)).fill(0xff));
    return abi.encode(["bytes", "bytes"], [dummyEcdsa, dummyPq]);
}

// ─── Main flow ──────────────────────────────────────────────────────────

export async function sendERC4337Transaction(
    accountAddress, targetAddress, value, callData,
    preQuantumSeed, signingMode, postQuantumSeed,
    provider, bundlerUrl, pqAlgo = 'mldsa'
) {
    const { pq, ecdsa } = getSigners(signingMode, pqAlgo);

    try {
        const network = await provider.getNetwork();

        console.log("Initialising signers…");

        if (signingMode === 'ledger') {
            await ecdsa.init();
            hwMldsa.setTransport(ecdsa.getTransport());
            await pq.init();
        } else {
            await ecdsa.init({ privateKey: preQuantumSeed });
            await pq.init({ postQuantumSeed });
        }

        // 1. Create base UserOp
        let userOp = await createBaseUserOperation(
            accountAddress, targetAddress, value, callData, provider, bundlerUrl
        );

        // 2. Dummy signature for gas estimation
        userOp.signature = getDummySignature(pqAlgo);

        // 3. Estimate gas
        const gasEstimates = await estimateUserOperationGas(userOp, bundlerUrl);

        // 4. Update gas limits
        userOp = updateUserOpWithGasEstimates(userOp, gasEstimates);

        // 5. Real sign
        if (signingMode === 'ledger') {
            const result = await signHybridUserOp(
                ecdsa.getTransport(),
                "m/44'/60'/0'/0/0",
                userOp,
                ENTRY_POINT_ADDRESS,
                network.chainId
            );
            const ecdsaSig = ethers.concat([
                result.ecdsaR,
                result.ecdsaS,
                ethers.toBeHex(result.ecdsaV + 27, 1),
            ]);
            const abi = ethers.AbiCoder.defaultAbiCoder();
            userOp.signature = abi.encode(["bytes", "bytes"], [ecdsaSig, result.mldsaSignature]);
        } else {
            userOp.signature = await signUserOpHybrid(
                userOp, ENTRY_POINT_ADDRESS, network.chainId, ecdsa, pq
            );
        }
        console.log("Signature ready.");

        // Submit or preview
        if (!bundlerUrl || bundlerUrl.trim() === '' || bundlerUrl.includes('example.com')) {
            console.log("UserOp signed — no bundler URL configured.");
            return { success: true, userOp, message: "UserOperation created and signed (bundler needed)" };
        }

        try {
            console.log("Submitting to bundler…");
            const userOpHash = await submitUserOperation(userOp, bundlerUrl, ENTRY_POINT_ADDRESS);
            console.log("Mining… " + userOpHash);

            const receipt = await waitForUserOperationReceipt(userOpHash, bundlerUrl);
            if (receipt) {
                const txHash = receipt.receipt?.transactionHash;
                if (receipt.success === false) {
                    console.error("Transaction reverted" + (txHash ? ": " + txHash : ""));
                } else {
                    console.log("Transaction mined: " + (txHash || userOpHash));
                }
            } else {
                console.log("Timed out — transaction may still be pending.");
            }

            return { success: true, userOpHash, receipt };
        } catch (error) {
            console.error("Bundler error: " + error.message);
            return { success: false, error: error.message, userOp };
        }

    } catch (error) {
        console.error("Transaction failed: " + error.message);
        return { success: false, error: error.message };
    } finally {
        await pq.cleanup();
        await ecdsa.cleanup();
    }
}

// ─── UI Setup ───────────────────────────────────────────────────────────

function setup() {
    const sendBtn       = document.getElementById('sendTx');
    const sendLedgerBtn = document.getElementById('sendTxLedger');
    const output        = document.getElementById('output');

    if (!output) { console.error('Missing UI elements'); return; }

    redirectConsole(output);

    // ── USB / Bluetooth transport toggle ──
    const transportUsb = document.getElementById('transport-usb');
    const transportBle = document.getElementById('transport-ble');
    if (transportUsb && transportBle) {
        transportUsb.addEventListener('click', () => {
            transportUsb.classList.add('active');
            transportBle.classList.remove('active');
            setTransportMode('usb');
        });
        transportBle.addEventListener('click', () => {
            transportBle.classList.add('active');
            transportUsb.classList.remove('active');
            setTransportMode('ble');
        });
    }

    console.log('Ready.');

    async function run(mode) {
        const btn = mode === 'ledger' ? sendLedgerBtn : sendBtn;
        if (btn) btn.disabled = true;
        output.innerHTML = '';

        try {
            const rpcUrl = document.getElementById('rpcUrl')?.value.trim();
            if (!rpcUrl) { console.error('Please enter an RPC URL.'); return; }

            console.log('Connecting…');
            console.log('RPC URL:', rpcUrl);
            const provider = new ethers.JsonRpcProvider(rpcUrl);
            const network = await provider.getNetwork();
            console.log('Chain ID:', network.chainId.toString());

            const pqAlgo = document.getElementById('pqAlgo')?.value || 'mldsa';

            let preQuantumSeed = '';
            let postQuantumSeed = '';

            if (mode !== 'ledger') {
                const mnemonic = document.getElementById('mnemonic').value.trim();
                if (!mnemonic) { console.error('Please enter a BIP-39 mnemonic phrase.'); return; }
                const derived = deriveSeeds(mnemonic, pqAlgo);
                preQuantumSeed = derived.preQuantumSeed;
                postQuantumSeed = derived.postQuantumSeed;
            }
            const pimlicoApiKey   = document.getElementById('pimlicoApiKey').value.trim();
            const accountAddress  = document.getElementById('accountAddress').value.trim();
            const targetAddress   = document.getElementById('targetAddress').value.trim();
            const valueEth        = document.getElementById('value').value.trim();
            const callData        = document.getElementById('callData').value.trim();

            const bundlerUrl = 'https://api.pimlico.io/v2/' + network.chainId + '/rpc?apikey=' + pimlicoApiKey;

            await sendERC4337Transaction(
                accountAddress, targetAddress, ethers.parseEther(valueEth), callData,
                preQuantumSeed, mode, postQuantumSeed,
                provider, bundlerUrl, pqAlgo
            );
        } catch (error) {
            console.error('Error: ' + error.message);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    if (sendBtn)       sendBtn.addEventListener('click', () => run('soft'));
    if (sendLedgerBtn) sendLedgerBtn.addEventListener('click', () => run('ledger'));
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
} else {
    setup();
}

// ─── Helpers ────────────────────────────────────────────────────────────

/**
 * Poll the bundler for a UserOperation receipt until it is mined.
 */
async function waitForUserOperationReceipt(
    userOpHash, bundlerUrl, timeoutMs = 120_000, intervalMs = 3_000
) {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        try {
            const response = await fetch(bundlerUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0', id: 1,
                    method: 'eth_getUserOperationReceipt',
                    params: [userOpHash]
                })
            });
            const result = await response.json();
            if (result.result) return result.result;
        } catch (_) { /* network hiccup — keep polling */ }

        await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
}
