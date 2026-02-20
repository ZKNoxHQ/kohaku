import {
    openTransport,
    getEcdsaPublicKey,
    signEcdsaHash,
} from './ledgerTransport.js';
import { keccak256, ethers } from 'ethers';

const DEFAULT_BIP32_PATH = "m/44'/60'/0'/0/0";
let _transport = null;
let _address   = null;
let _bip32Path = DEFAULT_BIP32_PATH;

export async function init(config = {}) {
    _bip32Path = config.bip32Path || DEFAULT_BIP32_PATH;
    if (!_transport) _transport = await openTransport();

    const pubkey = await getEcdsaPublicKey(_transport, _bip32Path);
    const raw  = pubkey.subarray(2, 66);
    const hash = keccak256(raw);
    _address = "0x" + hash.slice(-40);
}

export function getAddress() {
    if (!_address) throw new Error("Signer not initialized — call init() first");
    return _address;
}

export async function signHash(hash) {
    if (!_transport) throw new Error("Signer not initialized — call init() first");
    const { v, r, s } = await signEcdsaHash(_transport, _bip32Path, hash);
    const serialized = ethers.concat([r, s, ethers.toBeHex(v + 27, 1)]);
    return { serialized };
}

export async function cleanup() {
    if (_transport) {
        try { await _transport.close(); } catch (_) {}
        _transport = null;
        _address   = null;
        _bip32Path = DEFAULT_BIP32_PATH;
    }
}

export function getTransport() { return _transport; }
export function setTransport(t) { _transport = t; }
