/**
 * PQ-SLIP: key derivation for hybrid PQ + ECDSA accounts.
 *
 * ECDSA: standard BIP-32 derivation at m/44'/60'/0'/0/0 (same as MetaMask/Rabby/Ledger).
 * PQ:    SLIP-0010-style — HMAC-SHA512 with algorithm-specific keywords on the BIP-39 seed:
 *          - "ML-DSA-44 seed"  → ML-DSA post-quantum seed
 *          - "Falcon512 seed"  → Falcon-512 post-quantum seed
 *        The left 32 bytes of the HMAC output become the PQ seed.
 */

import { ethers } from 'ethers';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';

const PQ_KEYWORDS = {
    mldsa:   'ML-DSA-44 seed',
    falcon:  'Falcon512 seed',
};

function hexToU8(hex) {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    return Uint8Array.from(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function u8ToHex(bytes) {
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derive both ECDSA and PQ seeds from a BIP-39 mnemonic phrase.
 *
 * @param {string} mnemonic  BIP-39 mnemonic (12/15/18/21/24 words)
 * @param {string} pqAlgo    "mldsa" or "falcon"
 * @returns {{ preQuantumSeed: string, postQuantumSeed: string }}
 */
export function deriveSeeds(mnemonic, pqAlgo = 'mldsa') {
    const keyword = PQ_KEYWORDS[pqAlgo];
    if (!keyword) throw new Error('Unknown PQ algorithm: ' + pqAlgo);

    const phrase = mnemonic.trim();

    // ECDSA: standard BIP-32 HD derivation at m/44'/60'/0'/0/0
    const hdNode = ethers.HDNodeWallet.fromPhrase(phrase, "", "m/44'/60'/0'/0/0");
    const preQuantumSeed = hdNode.privateKey;

    // PQ: SLIP-10 derivation at m/44'/60'/0'/0/0 with algorithm-specific keyword
    const m = ethers.Mnemonic.fromPhrase(phrase);
    const masterSeed = hexToU8(m.computeSeed());

    // Master key: HMAC-SHA512(keyword, bip39Seed)
    const keywordBytes = new TextEncoder().encode(keyword);
    console.log("BIP39 seed: " + u8ToHex(masterSeed));
    console.log("HMAC key (keyword): " + keyword);
    const I = hmac(sha512, keywordBytes, masterSeed);
    let pqKey = I.slice(0, 32);
    let chainCode = I.slice(32);
    console.log("Master key: " + u8ToHex(pqKey));
    console.log("Master chaincode: " + u8ToHex(chainCode));

    // Child derivation (SLIP-10): m/44'/60'/0'/0/0
    // Ledger firmware forces all components to hardened (| 0x80000000)
    const path = [0x8000002c, 0x8000003c, 0x80000000, 0x80000000, 0x80000000];
    for (const index of path) {
        const data = new Uint8Array(1 + 32 + 4);
        data[0] = 0x00;
        data.set(pqKey, 1);
        data[33] = (index >>> 24) & 0xff;
        data[34] = (index >>> 16) & 0xff;
        data[35] = (index >>> 8) & 0xff;
        data[36] = index & 0xff;
        const child = hmac(sha512, chainCode, data);
        pqKey = child.slice(0, 32);
        chainCode = child.slice(32);
        console.log("Child 0x" + index.toString(16) + ": " + u8ToHex(pqKey));
    }

    const postQuantumSeed = u8ToHex(pqKey);

    return { preQuantumSeed, postQuantumSeed };
}
