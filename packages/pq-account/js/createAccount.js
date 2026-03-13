import { ethers } from 'ethers';
import { nttCompact, redirectConsole } from './utils.js';
import { to_expanded_encoded_bytes } from './utils_mldsa.js';
import { deriveSeeds } from './pqslip.js';
import * as softEcdsaKeygen from './software-signer/ecdsaKeygen.js';
import * as softMldsaKeygen from './software-signer/mldsaKeygen.js';
import * as softFalconKeygen from './software-signer/falconKeygen.js';
import {
    openTransport,
    deriveMldsaSeed,
    getMldsaPublicKey,
    getEcdsaPublicKey,
} from './hardware-signer/ledgerTransport.js';
import { LedgerEthSigner } from './LedgerEthSigner.js';

// ─── Helpers ────────────────────────────────────────────────────────────

/**
 * Encode a Falcon-512 public key for the on-chain verifier.
 */
function toFalconEncodedBytes(falconPublicKey) {
    if (falconPublicKey.length !== 1025)
        throw new Error("Expected 1025-byte Falcon-512 public key, got " + falconPublicKey.length);

    // 512 coefficients (16-bit big-endian), skipping the 1-byte header
    const coeffs = [];
    for (let i = 0; i < 512; i++) {
        const offset = 1 + i * 2;
        coeffs.push((falconPublicKey[offset] << 8) | falconPublicKey[offset + 1]);
    }

    const packed = nttCompact(coeffs);

    let hex = "0x";
    for (const word of packed) {
        hex += word.toString(16).padStart(64, "0");
    }
    return hex;
}

// ─── Main flow ──────────────────────────────────────────────────────────

async function main(mode) {
    const factoryAddress = document.getElementById('factory').textContent.trim();
    if (!factoryAddress || factoryAddress === '\u2014') {
        console.error("No factory address found for this network.");
        return;
    }

    const accountMode = document.getElementById('accountMode')?.value || 'mldsa_k1';
    const pqAlgo = accountMode.startsWith('falcon') ? 'falcon' : 'mldsa';

    let provider, signer, transport;

    try {
        if (mode === 'ledger') {
            if (pqAlgo === 'falcon') {
                console.error("Falcon is only available in software mode.");
                return;
            }

            const rpcUrl = document.getElementById('rpcUrl')?.value.trim();
            if (!rpcUrl) { console.error("Please enter an RPC URL."); return; }

            provider = new ethers.JsonRpcProvider(rpcUrl);
            await provider.getNetwork();

            console.log("Connecting to Ledger…");
            transport = await openTransport();
            signer = new LedgerEthSigner(transport, provider);
            await signer.getAddress();
        } else {
            if (typeof window === 'undefined' || !window.ethereum) {
                throw new Error(
                    "No wallet detected. Install MetaMask or Rabby."
                );
            }

            const networkToChainId = {
                sepolia: '0xaa36a7',
                arbitrumSepolia: '0x66eee', baseSepolia: '0x14a34',
            };
            const selectedNetwork = document.getElementById('targetNetwork')?.value;
            const expectedChainHex = networkToChainId[selectedNetwork];

            await window.ethereum.request({ method: 'eth_requestAccounts' });

            const currentChain = await window.ethereum.request({ method: 'eth_chainId' });
            if (expectedChainHex && currentChain.toLowerCase() !== expectedChainHex.toLowerCase()) {
                try {
                    await window.ethereum.request({
                        method: 'wallet_switchEthereumChain',
                        params: [{ chainId: expectedChainHex }],
                    });
                } catch (_) {
                    throw new Error("Please switch your wallet to " + selectedNetwork + ".");
                }
            }

            console.log("Connecting wallet…");
            provider = new ethers.BrowserProvider(window.ethereum);
            signer = await provider.getSigner();
        }

        // Get public keys
        let preQuantumPubKey, pqPublicKey;

        console.log("Deriving keys…");
        if (mode === 'ledger') {
            const ecdsaPubkey = await getEcdsaPublicKey(transport, "m/44'/60'/0'/0/0");
            const raw = ecdsaPubkey.subarray(2, 66);
            const hash = ethers.keccak256(raw);
            preQuantumPubKey = ethers.getAddress('0x' + hash.slice(-40));

            const mldsaSeed = await deriveMldsaSeed(transport, "m/44'/60'/0'/0/0");
            console.log("Ledger PQ seed: " + Array.from(mldsaSeed).map(b => b.toString(16).padStart(2, '0')).join(''));
            pqPublicKey = await getMldsaPublicKey(transport);
            console.log("Ledger PQ pubkey (first 32): " + Array.from(pqPublicKey.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(''));
        } else {
            const mnemonic = document.getElementById('mnemonic').value.trim();
            if (!mnemonic) {
                console.error("Please enter a BIP-39 mnemonic phrase.");
                return;
            }

            const { preQuantumSeed, postQuantumSeed } = deriveSeeds(mnemonic, pqAlgo);
            console.log("Software PQ seed: " + postQuantumSeed);

            preQuantumPubKey = await softEcdsaKeygen.getAddress({ privateKey: preQuantumSeed });

            if (pqAlgo === 'falcon') {
                pqPublicKey = await softFalconKeygen.getPublicKey({ postQuantumSeed });
            } else {
                pqPublicKey = await softMldsaKeygen.getPublicKey({ postQuantumSeed });
            }
            console.log("Software PQ pubkey (first 32): " + Array.from(pqPublicKey.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(''));
        }

        console.log("ECDSA address: " + preQuantumPubKey);

        // Encode keys for the contract
        const postQuantumPubKey = pqAlgo === 'falcon'
            ? toFalconEncodedBytes(pqPublicKey)
            : to_expanded_encoded_bytes(pqPublicKey);

        // Deploy
        console.log("Deploying account…");
        const result = await deployERC4337Account(
            factoryAddress, preQuantumPubKey, postQuantumPubKey, signer
        );

        if (result.success) {
            if (result.alreadyExists) {
                console.log("Account already exists: " + result.address);
            } else {
                console.log("Account created: " + result.address);
            }
        } else {
            console.error("Deployment failed" + (result.error ? ": " + result.error : ""));
        }

    } finally {
        if (transport) {
            try { await transport.close(); } catch (_) { }
        }
    }
}

// ─── UI Setup ───────────────────────────────────────────────────────────

function setup() {
    const deployBtn = document.getElementById('deploy');
    const deployLedgerBtn = document.getElementById('deploy-ledger');
    const output = document.getElementById('output');

    if (!output) { console.error('Missing UI elements'); return; }

    redirectConsole(output);

    console.log('Ready.');

    // Disable Ledger button when Falcon is selected
    const accountModeSelect = document.getElementById('accountMode');
    if (accountModeSelect && deployLedgerBtn) {
        accountModeSelect.addEventListener('change', () => {
            const isFalcon = accountModeSelect.value.startsWith('falcon');
            deployLedgerBtn.disabled = isFalcon;
            deployLedgerBtn.title = isFalcon ? 'Falcon is only available in software mode' : '';
        });
    }

    async function run(mode) {
        const btn = mode === 'ledger' ? deployLedgerBtn : deployBtn;
        if (btn) btn.disabled = true;
        output.innerHTML = '';

        try {
            await main(mode);
        } catch (error) {
            console.error('Error: ' + error.message);
            if (error.code === 'ACTION_REJECTED' || error.code === 4001) {
                console.log("(User rejected the transaction)");
            }
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    if (deployBtn) deployBtn.addEventListener('click', () => run('soft'));
    if (deployLedgerBtn) deployLedgerBtn.addEventListener('click', () => run('ledger'));
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
} else {
    setup();
}

// ─── Factory ABI & deployment ───────────────────────────────────────────

const ACCOUNT_FACTORY_ABI = [
    "function createAccount(bytes calldata preQuantumPubKey, bytes calldata postQuantumPubKey) external returns (address)",
    "function getAddress(bytes calldata preQuantumPubKey, bytes calldata postQuantumPubKey) external view returns (address payable)",
    "function entryPoint() external view returns (address)",
    "function preQuantumLogic() external view returns (address)",
    "function postQuantumLogic() external view returns (address)",
    "function hybridVerifierLogic() external view returns (address)"
];

/**
 * Deploy an ERC-4337 account via the factory contract.
 */
export async function deployERC4337Account(
    factoryAddress,
    preQuantumPubKey,
    postQuantumPubKey,
    signerOrProvider
) {
    try {
        let provider, signer;

        if (typeof signerOrProvider === "string") {
            provider = new ethers.JsonRpcProvider(signerOrProvider);
            if (provider.getSigner) {
                signer = provider.getSigner();
            }

        } else if (signerOrProvider.signTransaction) {
            signer = signerOrProvider;
            provider = signer.provider;

        } else if (signerOrProvider.request) {
            provider = new ethers.BrowserProvider(signerOrProvider);
            signer = await provider.getSigner();

        } else if (signerOrProvider.getNetwork) {
            provider = signerOrProvider;
            signer = await provider.getSigner();

        } else {
            throw new Error(
                "Invalid signer or provider. Please provide window.ethereum, a Signer, a Provider, or an RPC URL string."
            );
        }

        const network = await provider.getNetwork();

        const factoryCode = await provider.getCode(factoryAddress);
        if (factoryCode === '0x') {
            throw new Error("No contract deployed at factory address!");
        }

        const factory = new ethers.Contract(factoryAddress, ACCOUNT_FACTORY_ABI, signer);

        let expectedAddress;
        try {
            const getAddressFn = factory.getFunction("getAddress");
            expectedAddress = await getAddressFn.staticCall(
                preQuantumPubKey,
                postQuantumPubKey
            );
        } catch (error) {
            throw new Error("Cannot calculate account address: " + error.message);
        }

        if (!ethers.isAddress(expectedAddress)) {
            throw new Error("Invalid address returned from getAddress()");
        }

        const code = await provider.getCode(expectedAddress);
        if (code !== '0x') {
            return {
                success: true,
                address: expectedAddress,
                alreadyExists: true
            };
        }

        let estimatedGas;
        try {
            estimatedGas = await factory.createAccount.estimateGas(
                preQuantumPubKey,
                postQuantumPubKey
            );
        } catch (error) {
            estimatedGas = 5000000n;
        }
        const feeData = await provider.getFeeData();

        let maxFee, maxPriority;

        if (network.chainId === 84532n || network.chainId === 8453n) {
            // Base Sepolia / Base Mainnet
            maxPriority = 0n;
            maxFee = feeData.maxFeePerGas ?? 1_000_000n;
        } else {
            // Other chains (keep your logic)
            const minTip = 1_000_000n;
            maxPriority = feeData.maxPriorityFeePerGas > minTip
                ? feeData.maxPriorityFeePerGas
                : minTip;

            maxFee = feeData.maxFeePerGas
                ? feeData.maxFeePerGas * 2n
                : maxPriority * 2n;
        }

        console.log("Confirm the transaction in your wallet…");

        const tx = await factory.createAccount(
            preQuantumPubKey,
            postQuantumPubKey,
            {
                gasLimit: estimatedGas * 120n / 100n,
                maxFeePerGas: maxFee,
                maxPriorityFeePerGas: maxPriority,
            }
        );
        const txHash = tx.hash;
        console.log("Mining… " + txHash);

        let receipt = null;
        let attempts = 0;
        const maxAttempts = 60;

        while (!receipt && attempts < maxAttempts) {
            try {
                receipt = await provider.getTransactionReceipt(txHash);
                if (!receipt) {
                    attempts++;
                    await new Promise(resolve => setTimeout(resolve, 5000));
                }
            } catch (error) {
                attempts++;
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }

        if (!receipt) {
            console.log("Transaction pending — check explorer for " + txHash);
            return {
                success: false,
                pending: true,
                transactionHash: txHash,
                expectedAddress
            };
        }

        if (receipt.status === 0) {
            return {
                success: false,
                error: "Transaction reverted",
                transactionHash: txHash
            };
        }

        return {
            success: true,
            address: expectedAddress,
            transactionHash: txHash,
            blockNumber: receipt.blockNumber,
            gasUsed: receipt.gasUsed.toString(),
        };

    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}
