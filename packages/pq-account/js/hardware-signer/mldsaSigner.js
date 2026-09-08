import {
    openTransport,
    signMldsa,
    getMldsaPublicKey,
} from './ledgerTransport.js';

const DEFAULT_BIP32_PATH = "m/44'/60'/0'/0/0";
let _transport = null;
let _bip32Path = DEFAULT_BIP32_PATH;

// init() no longer pre-loads state on-device (the pre-port GET_MLDSA_SEED
// step is gone). We stash the path locally and hand it to every signing /
// keygen call — each of those now includes the seed derivation on-device
// in a single INS.
export async function init(config = {}) {
    _bip32Path = config.bip32Path || DEFAULT_BIP32_PATH;
    if (!_transport) _transport = await openTransport();
}

export async function sign(messageBytes) {
    if (!_transport) throw new Error("Signer not initialized — call init() first");
    return signMldsa(_transport, _bip32Path, messageBytes);
}

export async function getPublicKey() {
    if (!_transport) throw new Error("Signer not initialized — call init() first");
    return getMldsaPublicKey(_transport, _bip32Path);
}

export async function cleanup() {
    if (_transport) {
        try { await _transport.close(); } catch (_) {}
        _transport = null;
    }
}

export function getTransport() { return _transport; }
export function setTransport(t) { _transport = t; }
