/**
 * Low-level Ledger APDU transport for ECDSA + ML-DSA commands.
 *
 * Firmware handlers (app-mldsa, since the ZKNOX port):
 *   GET_PUBLIC_KEY     (0x05)  → ECDSA public key
 *   SIGN_DILITHIUM     (0x0f)  → init / absorb / finalize signing
 *   KEYGEN_DILITHIUM   (0x11)  → derive ML-DSA-44 keypair from BIP32 path
 *                                (path in cdata; personalization "ML-DSA-44 seed")
 *   GET_SIG_CHUNK      (0x12)  → retrieve signature chunks (bounds-checked)
 *   GET_PK_CHUNK       (0x13)  → retrieve public key chunks (bounds-checked)
 *   ECDSA_SIGN_HASH    (0x15)  → blind-sign 32-byte hash with ECDSA
 *   HYBRID_SIGN_HASH   (0x16)  → single-confirm hybrid blind-sign
 *   HYBRID_SIGN_USEROP (0x17)  → clear-sign ERC-4337 UserOp
 *
 * Diverges from the pre-port ZKNOX firmware:
 *   - GET_MLDSA_SEED (0x14) was removed (host must never see the seed).
 *   - KEYGEN_DILITHIUM moved from 0x0c to 0x11; takes a BIP32 path in cdata
 *     instead of relying on a pre-loaded seed.
 *   - SIGN_DILITHIUM finalize returns SW only; the client fetches the full
 *     signature via GET_SIG_CHUNK (no first-256-B inline chunk).
 *
 * Path hardening: the ML-DSA seed derivation on-device requires an
 * all-hardened path (SLIP-0010 ed25519-mode requirement). The firmware's
 * mldsa_derive_seed helper forces the hardened bit on every component
 * before calling the SDK, so callers can pass any path here — including
 * the standard non-hardened Ethereum path "m/44'/60'/0'/0/0" — and the
 * ECDSA half of hybrid signing (0x16/0x17) will derive from the raw
 * path (matching the account's stored ECDSA address), while the ML-DSA
 * half derives from the same path with hardening forced.
 */

import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import { ethers } from 'ethers';

let _transportMode = 'usb';   // 'usb' | 'ble'

export function setTransportMode(mode) { _transportMode = mode; }
export function getTransportMode()     { return _transportMode; }

const CLA = 0xe0;

const INS = {
    GET_PUBLIC_KEY:     0x05,
    SIGN_DILITHIUM:     0x0f,
    KEYGEN_DILITHIUM:   0x11,   // was 0x0c pre-port; takes a BIP32 path now
    GET_SIG_CHUNK:      0x12,
    GET_PK_CHUNK:       0x13,
    ECDSA_SIGN_HASH:    0x15,
    HYBRID_SIGN_HASH:   0x16,
    HYBRID_SIGN_USEROP: 0x17,
};

export const MLDSA44_SIG_BYTES = 2420;
export const MLDSA44_PK_BYTES  = 1312;
const CHUNK_SIZE = 255;

// ─── Helpers ────────────────────────────────────────────────────────────

function encodeBip32Path(path) {
    const components = path
        .replace("m/", "")
        .split("/")
        .map(c => {
            const hardened = c.endsWith("'");
            const val = parseInt(hardened ? c.slice(0, -1) : c, 10);
            return hardened ? (val + 0x80000000) >>> 0 : val;
        });

    const buf = Buffer.alloc(1 + components.length * 4);
    buf[0] = components.length;
    components.forEach((c, i) => buf.writeUInt32BE(c, 1 + i * 4));
    return buf;
}

async function sendApdu(transport, ins, p1, p2, data) {
    const payload  = data ? Buffer.from(data) : Buffer.alloc(0);
    const response = await transport.send(CLA, ins, p1, p2, payload);
    return response.subarray(0, response.length - 2);
}

async function readChunked(transport, ins, totalBytes) {
    const buf = Buffer.alloc(totalBytes);
    for (let p1 = 0; p1 * CHUNK_SIZE < totalBytes; p1++) {
        const offset    = p1 * CHUNK_SIZE;
        const remaining = totalBytes - offset;
        const p2        = Math.min(remaining, CHUNK_SIZE);
        const chunk     = await sendApdu(transport, ins, p1, p2, null);
        chunk.copy(buf, offset, 0, p2);
    }
    return new Uint8Array(buf);
}

function bigintTo32BE(val) {
    const hex = BigInt(val).toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
}

function addressToBytes(addr) {
    return Buffer.from(addr.replace(/^0x/, ''), 'hex');
}

/**
 * Parse an ECDSA DER response from the device into { v, r, s }.
 * Response layout: sig_len(1) | DER(r,s) | v(1)
 */
function parseEcdsaResponse(resp) {
    const derLen = resp[0];
    const der    = resp.subarray(1, 1 + derLen);
    const v      = resp[1 + derLen];

    // DER: 30 <len> 02 <rlen> <r> 02 <slen> <s>
    let offset = 2; // skip 30 <len>
    offset++;       // skip 02
    const rLen = der[offset++];
    const rRaw = der.subarray(offset, offset + rLen);
    offset += rLen;
    offset++;       // skip 02
    const sLen = der[offset++];
    const sRaw = der.subarray(offset, offset + sLen);

    // Pad/trim to 32 bytes
    const r = new Uint8Array(32);
    const s = new Uint8Array(32);
    r.set(rRaw.subarray(rRaw.length - 32));
    s.set(sRaw.subarray(sRaw.length - 32));

    return { v, r, s };
}

// ─── Public API ─────────────────────────────────────────────────────────

export async function openTransport(mode) {
    const m = mode || _transportMode;
    if (m === 'ble') {
        const { default: TransportWebBLE } = await import("@ledgerhq/hw-transport-web-ble");
        return TransportWebBLE.create();
    }
    return TransportWebHID.create();
}

/**
 * Open a Ledger transport via Bluetooth (Web BLE).
 * Requires HTTPS and a Bluetooth-capable Ledger (Nano X, Stax, Flex).
 */
export async function openTransportBLE() {
    return openTransport('ble');
}

/**
 * Derive the ML-DSA-44 keypair on-device from a BIP32 path (SLIP-0010 with
 * personalization "ML-DSA-44 seed"), and return the 1312-byte public key.
 *
 * The secret key never leaves the secure element. The device stores the
 * derived pk and seed in RAM until the next keygen/sign operation.
 */
export async function getMldsaPublicKey(transport, bip32Path) {
    await sendApdu(transport, INS.KEYGEN_DILITHIUM, 0x00, 0x00, encodeBip32Path(bip32Path));
    return readChunked(transport, INS.GET_PK_CHUNK, MLDSA44_PK_BYTES);
}

/**
 * Sign arbitrary bytes with ML-DSA-44 on the Ledger.
 *
 * Runs KEYGEN_DILITHIUM first to load the key for @p bip32Path, so this
 * function is self-sufficient (pre-port ZKNOX required a separate
 * deriveMldsaSeed step; that's now folded in).
 *
 * Flow: keygen (path) → init → absorb (chunked) → finalize (user approval
 * on-device) → read signature via chunk fetch.
 */
export async function signMldsa(transport, bip32Path, messageBytes) {
    // Load the ML-DSA key for this path. SIGN_DILITHIUM's init step refuses
    // to run unless mldsa_seed is non-zero, so this step is required —
    // there is no "seed already loaded" fast path anymore.
    await sendApdu(transport, INS.KEYGEN_DILITHIUM, 0x00, 0x00, encodeBip32Path(bip32Path));

    // 0x00 init: reset the signing accumulator on-device.
    await sendApdu(transport, INS.SIGN_DILITHIUM, 0x00, 0x00, null);

    // 0x01 absorb: stream the payload into the on-device accumulator.
    const MAX_APDU_DATA = 250;
    for (let offset = 0; offset < messageBytes.length; offset += MAX_APDU_DATA) {
        const chunk = messageBytes.slice(offset, Math.min(offset + MAX_APDU_DATA, messageBytes.length));
        await sendApdu(transport, INS.SIGN_DILITHIUM, 0x01, 0x00, chunk);
    }

    // 0x80 finalize: triggers on-device user approval, then signs. Our port
    // accepts (and ignores) the ZKNOX 2-byte msg_len header; kept here so
    // the wire matches ZKNOX for anyone sniffing.
    const msgLenBuf = Buffer.alloc(2);
    msgLenBuf.writeUInt16BE(messageBytes.length, 0);
    await sendApdu(transport, INS.SIGN_DILITHIUM, 0x80, 0x00, msgLenBuf);

    return readChunked(transport, INS.GET_SIG_CHUNK, MLDSA44_SIG_BYTES);
}

/**
 * Get the ECDSA public key (65 bytes uncompressed) for the given BIP32 path.
 */
export async function getEcdsaPublicKey(transport, bip32Path) {
    const pathData = encodeBip32Path(bip32Path);
    return new Uint8Array(await sendApdu(transport, INS.GET_PUBLIC_KEY, 0x00, 0x00, pathData));
}

/**
 * Blind-sign a 32-byte hash with ECDSA on the Ledger.
 */
export async function signEcdsaHash(transport, bip32Path, hash) {
    if (hash.length !== 32) throw new Error("Hash must be 32 bytes");

    const pathData = encodeBip32Path(bip32Path);
    const payload  = Buffer.concat([pathData, Buffer.from(hash)]);
    const resp     = await sendApdu(transport, INS.ECDSA_SIGN_HASH, 0x00, 0x00, payload);

    return parseEcdsaResponse(resp);
}

/**
 * Hybrid blind-sign: single user confirmation → ECDSA + ML-DSA signatures.
 *
 * Path is passed as-is: the on-device ECDSA half signs over the raw path
 * (so `m/44'/60'/0'/0/0` produces the standard Ethereum address that
 * matches the account's stored ECDSA pk), while the ML-DSA half's
 * SLIP-0010 derivation forces hardening internally on the firmware side.
 */
export async function signHybridHash(transport, bip32Path, hash) {
    if (hash.length !== 32) throw new Error("Hash must be 32 bytes");

    const pathData = encodeBip32Path(bip32Path);
    const payload  = Buffer.concat([pathData, Buffer.from(hash)]);
    const resp     = await sendApdu(transport, INS.HYBRID_SIGN_HASH, 0x00, 0x00, payload);

    const { v, r, s }   = parseEcdsaResponse(resp);
    const mldsaSignature = await readChunked(transport, INS.GET_SIG_CHUNK, MLDSA44_SIG_BYTES);

    return { ecdsaV: v, ecdsaR: r, ecdsaS: s, mldsaSignature };
}

/**
 * Hybrid clear-sign an ERC-4337 v0.7 UserOperation.
 *
 * Sends four APDUs so the device can recompute the UserOpHash on-chip
 * and display human-readable fields before signing with both algorithms.
 */
export async function signHybridUserOp(transport, bip32Path, userOp, entryPoint, chainId) {
    const I = INS.HYBRID_SIGN_USEROP;

    // APDU 1: BIP32 path — passed as-is; ECDSA uses raw path, ML-DSA
    // derivation forces hardening on the firmware side.
    await sendApdu(transport, I, 0x00, 0x00, encodeBip32Path(bip32Path));

    // APDU 2: chain_id(32) | entry_point(20) | sender(20) | nonce(32)
    await sendApdu(transport, I, 0x01, 0x00, Buffer.concat([
        bigintTo32BE(chainId),
        addressToBytes(entryPoint),
        addressToBytes(userOp.sender),
        bigintTo32BE(userOp.nonce),
    ]));

    // APDU 3: six 32-byte packed fields
    await sendApdu(transport, I, 0x02, 0x00, Buffer.concat([
        ethers.getBytes(ethers.keccak256(userOp.initCode)),
        ethers.getBytes(ethers.keccak256(userOp.callData)),
        ethers.getBytes(userOp.accountGasLimits),
        bigintTo32BE(userOp.preVerificationGas),
        ethers.getBytes(userOp.gasFees),
        ethers.getBytes(ethers.keccak256(userOp.paymasterAndData)),
    ]));

    // APDU 4: raw callData (triggers NBGL review on device)
    const rawCallData = ethers.getBytes(userOp.callData);
    const callDataPayload = rawCallData.length <= CHUNK_SIZE
        ? Buffer.from(rawCallData)
        : Buffer.alloc(0);

    const resp = await sendApdu(transport, I, 0x03, 0x00, callDataPayload);

    const { v, r, s }   = parseEcdsaResponse(resp);
    const mldsaSignature = await readChunked(transport, INS.GET_SIG_CHUNK, MLDSA44_SIG_BYTES);

    return { ecdsaV: v, ecdsaR: r, ecdsaS: s, mldsaSignature };
}
