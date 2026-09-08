import { openTransport, getMldsaPublicKey } from './ledgerTransport.js';

const DEFAULT_BIP32_PATH = "m/44'/60'/0'/0/0";

export async function getPublicKey(config = {}) {
    const bip32Path = config.bip32Path || DEFAULT_BIP32_PATH;
    const transport = await openTransport();

    try {
        // getMldsaPublicKey now derives the seed on-device (via KEYGEN_DILITHIUM
        // INS 0x11) and returns the pk in one call — the pre-port deriveMldsaSeed
        // step (INS 0x14) was removed for security (seed no longer leaves device).
        const publicKey = await getMldsaPublicKey(transport, bip32Path);
        console.log("✅ ML-DSA public key retrieved (" + publicKey.length + " bytes)");
        return publicKey;
    } finally {
        await transport.close();
    }
}
