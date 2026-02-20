/**
 * Elliptic Curve Wrapper for secp256k1
 * Port of ledgerblue/ecWrapper.py
 * 
 * Uses @noble/secp256k1 v3 for cryptographic operations
 * 
 * CRITICAL: noble v3 sign()/verify() hash internally with SHA256.
 *   - raw=false → pass raw msg to sign(), it will hash once (matching Python/device)
 *   - raw=true  → msg is already hashed, use { prehashed: true } to skip internal hash
 */

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { randomBytes } from '@noble/hashes/utils.js';

// Configure secp256k1 sync hashes (v3 API)
secp256k1.hashes.sha256 = (msg) => sha256(msg);
secp256k1.hashes.hmacSha256 = (key, ...msgs) => hmac(sha256, key, secp256k1.etc.concatBytes(...msgs));

// secp256k1 curve order for low-S normalization
const SECP256K1_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const HALF_ORDER = SECP256K1_ORDER / 2n;

/**
 * Convert compact signature (64 bytes r||s) to DER format
 */
function compactToDER(compact) {
    const r = compact.slice(0, 32);
    const s = compact.slice(32, 64);
    
    let rStart = 0;
    while (rStart < r.length - 1 && r[rStart] === 0) rStart++;
    let rBytes = r.slice(rStart);
    
    let sStart = 0;
    while (sStart < s.length - 1 && s[sStart] === 0) sStart++;
    let sBytes = s.slice(sStart);
    
    if (rBytes[0] & 0x80) {
        const newR = new Uint8Array(rBytes.length + 1);
        newR[0] = 0;
        newR.set(rBytes, 1);
        rBytes = newR;
    }
    if (sBytes[0] & 0x80) {
        const newS = new Uint8Array(sBytes.length + 1);
        newS[0] = 0;
        newS.set(sBytes, 1);
        sBytes = newS;
    }
    
    const totalLen = 2 + rBytes.length + 2 + sBytes.length;
    const der = new Uint8Array(2 + totalLen);
    let offset = 0;
    der[offset++] = 0x30;
    der[offset++] = totalLen;
    der[offset++] = 0x02;
    der[offset++] = rBytes.length;
    der.set(rBytes, offset);
    offset += rBytes.length;
    der[offset++] = 0x02;
    der[offset++] = sBytes.length;
    der.set(sBytes, offset);
    return der;
}

/**
 * Parse DER signature to compact (64 bytes r||s)
 */
function derToCompact(der) {
    if (der[0] !== 0x30) throw new Error('Invalid DER: missing SEQUENCE tag');
    let offset = 2;
    
    if (der[offset] !== 0x02) throw new Error('Invalid DER: missing INTEGER for r');
    offset++;
    const rLen = der[offset++];
    const rRaw = der.slice(offset, offset + rLen);
    offset += rLen;
    
    if (der[offset] !== 0x02) throw new Error('Invalid DER: missing INTEGER for s');
    offset++;
    const sLen = der[offset++];
    const sRaw = der.slice(offset, offset + sLen);
    
    const compact = new Uint8Array(64);
    const rTrim = rRaw[0] === 0 && rRaw.length > 32 ? rRaw.slice(1) : rRaw;
    compact.set(rTrim, 32 - rTrim.length);
    const sTrim = sRaw[0] === 0 && sRaw.length > 32 ? sRaw.slice(1) : sRaw;
    compact.set(sTrim, 64 - sTrim.length);
    return compact;
}

/**
 * Ensure compact signature has low-S
 */
function ensureLowS(compact) {
    const s = bytesToBigInt(compact.slice(32, 64));
    if (s > HALF_ORDER) {
        const newS = SECP256K1_ORDER - s;
        const result = new Uint8Array(64);
        result.set(compact.slice(0, 32));
        result.set(bigIntToBytes(newS, 32), 32);
        return result;
    }
    return compact;
}

/**
 * PublicKey class
 */
export class PublicKey {
    constructor(pubkey = null, raw = false) {
        if (pubkey === null) { this._point = null; return; }
        if (!raw) throw new Error('Non-raw init not supported');
        this._pubkeyBytes = new Uint8Array(pubkey);
        this._point = secp256k1.Point.fromBytes(pubkey);
    }

    serialize(compressed = true) {
        return this._point.toBytes(compressed);
    }

    /** Deserialize DER sig → compact 64 bytes */
    ecdsaDeserialize(serSig) {
        return derToCompact(serSig);
    }

    /** ECDH: SHA256(compressed_shared_point) - matches Python ledgerblue */
    ecdh(scalar) {
        const sharedPoint = this._point.multiply(bytesToBigInt(scalar));
        return sha256(sharedPoint.toBytes(true));
    }

    tweakAdd(scalar) {
        const tweakPoint = secp256k1.Point.BASE.multiply(bytesToBigInt(scalar));
        this._point = this._point.add(tweakPoint);
    }

    /**
     * Verify ECDSA signature
     * noble v3: verify() hashes internally with SHA256
     *   raw=false → pass raw msg, verify() hashes it (single hash)
     *   raw=true  → msg is already hashed, use {prehashed:true}
     */
    ecdsaVerify(msg, rawSig, raw = false) {
        let compact;
        if (rawSig.length === 64) {
            compact = rawSig;
        } else if (rawSig[0] === 0x30) {
            compact = derToCompact(rawSig);
        } else {
            compact = rawSig;
        }
        
        if (raw) {
            // msg is already a hash - don't hash again
            return secp256k1.verify(compact, msg, this._point.toBytes(false), { prehashed: true });
        } else {
            // let verify() hash internally (single SHA256)
            return secp256k1.verify(compact, msg, this._point.toBytes(false));
        }
    }
}

/**
 * PrivateKey class
 */
export class PrivateKey {
    constructor(privkey = null) {
        if (privkey === null) {
            this._privateKey = secp256k1.utils.randomSecretKey();
        } else {
            this._privateKey = new Uint8Array(privkey);
        }
        this.pubkey = new PublicKey(secp256k1.getPublicKey(this._privateKey, false), true);
    }

    serialize() { return bytesToHex(this._privateKey); }
    getPrivateKeyBytes() { return this._privateKey; }

    /** Serialize compact sig (64 bytes) → DER with low-S */
    ecdsaSerialize(rawSig) {
        if (rawSig instanceof Uint8Array && rawSig.length === 64) {
            return compactToDER(ensureLowS(rawSig));
        }
        return rawSig;
    }

    /**
     * Sign message with ECDSA
     * noble v3: sign() hashes internally with SHA256
     *   raw=false → pass raw msg to sign(), it hashes once (matches Python/device)
     *   raw=true  → msg is already hashed, use {prehashed:true}
     */
    ecdsaSign(msg, raw = false) {
        if (raw) {
            // msg is already a hash - don't hash again
            return secp256k1.sign(msg, this._privateKey, { prehashed: true });
        } else {
            // let sign() hash internally (single SHA256, matches Python secp256k1.ecdsa_sign)
            return secp256k1.sign(msg, this._privateKey);
        }
    }
}

// --- Utilities ---

function bytesToBigInt(bytes) {
    let result = 0n;
    for (const byte of bytes) result = (result << 8n) | BigInt(byte);
    return result;
}

function bigIntToBytes(num, length) {
    const bytes = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) { bytes[i] = Number(num & 0xffn); num >>= 8n; }
    return bytes;
}

export function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('Hex string must have even length');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
}

export default { PrivateKey, PublicKey, bytesToHex, hexToBytes };
