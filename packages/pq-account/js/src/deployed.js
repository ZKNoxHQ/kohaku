/**
 * Secure Channel Protocol (SCP) Establishment
 * Port of ledgerblue/deployed.py
 * 
 * Handles ECDH key exchange and certificate chain validation with Ledger devices
 */

import { PrivateKey, PublicKey, bytesToHex, hexToBytes } from './ecWrapper.js';
import { randomBytes } from '@noble/hashes/utils.js';

function uint32ToBytes(val) {
    return new Uint8Array([(val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff]);
}

/**
 * Establish SCP V2/V3 session (Nano S 1.4+, all modern devices)
 * 
 * Protocol flow:
 *   E004 IDENTIFY → E050 GET_NONCE → E051 VALIDATE_CERT (master) →
 *   E051 VALIDATE_CERT (ephemeral, P1=0x80) → E052 GET_CERT ×2 → E053 COMMIT
 * 
 * @param {object} dongle - Transport object with exchange/exchangeRaw methods
 * @param {Uint8Array} masterPrivate - Master private key (32 bytes)
 * @param {number} targetId - Target device ID (e.g. 0x33100004)
 * @param {Array|null} signerCertChain - Optional signer certificate chain
 * @param {number|null} ecdhSecretFormat - Force specific ECDH format
 */
export async function getDeployedSecretV2(dongle, masterPrivate, targetId, signerCertChain = null, ecdhSecretFormat = null) {
    const testMaster = new PrivateKey(masterPrivate);
    const testMasterPublic = testMaster.pubkey.serialize(false); // 65 bytes uncompressed
    const targetIdBytes = uint32ToBytes(targetId);

    if ((targetId & 0xf) < 2) {
        throw new Error('Target ID does not support SCP V2+');
    }

    // --- Helper: exchange returning {data, sw} without throwing ---
    async function rawExchange(apdu) {
        if (typeof dongle.exchangeRaw === 'function') {
            return await dongle.exchangeRaw(apdu);
        }
        try {
            const data = await dongle.exchange(apdu);
            return { data, sw: 0x9000 };
        } catch (e) {
            if (e.sw) return { data: e.data || new Uint8Array(0), sw: e.sw };
            throw e;
        }
    }

    // --- Step 1: IDENTIFY ---
    // Python: apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
    console.log(`SCP: IDENTIFY targetId=0x${targetId.toString(16)}`);
    let apdu = new Uint8Array([0xe0, 0x04, 0x00, 0x00, targetIdBytes.length, ...targetIdBytes]);
    let result = await rawExchange(apdu);
    if (result.sw !== 0x9000) {
        console.warn(`SCP: IDENTIFY SW=0x${result.sw.toString(16)}`);
    }

    // --- Step 2: GET_NONCE ---
    // Python: apdu = bytearray([0xe0, 0x50, 0x00, 0x00]) + bytearray([len(nonce)]) + nonce
    const nonce = randomBytes(8);
    apdu = new Uint8Array([0xe0, 0x50, 0x00, 0x00, nonce.length, ...nonce]);
    result = await rawExchange(apdu);
    
    if (result.sw !== 0x9000) {
        throw new Error(`SCP: GET_NONCE failed SW=0x${result.sw.toString(16)}`);
    }
    
    const authInfo = result.data;
    if (authInfo.length < 12) {
        throw new Error(`SCP: GET_NONCE insufficient data: ${authInfo.length} bytes (need 12+)`);
    }
    
    const batchSignerSerial = authInfo.slice(0, 4);
    const deviceNonce = authInfo.slice(4, 12);
    console.log(`SCP: GET_NONCE ok, batchSigner=${bytesToHex(batchSignerSerial)}, nonce=${bytesToHex(nonce)}, deviceNonce=${bytesToHex(deviceNonce)}`);

    // --- Step 3: VALIDATE_CERT (master certificate) ---
    // Python: apdu = bytearray([0xE0, 0x51, 0x00, 0x00]) + bytearray([len(certificate)]) + certificate
    if (signerCertChain) {
        for (const cert of signerCertChain) {
            apdu = new Uint8Array([0xe0, 0x51, 0x00, 0x00, cert.length, ...cert]);
            result = await rawExchange(apdu);
            if (result.sw !== 0x9000) {
                console.warn(`SCP: Signer cert SW=0x${result.sw.toString(16)}`);
            }
        }
    } else {
        console.log('SCP: Using test master key (self-signed)');

        // Self-signed master certificate: sign(sha256(0x01 || masterPublic))
        const dataToSign = new Uint8Array([0x01, ...testMasterPublic]);
        const signature = testMaster.ecdsaSign(dataToSign);
        const signatureDer = testMaster.ecdsaSerialize(signature);
        console.log(`SCP: Master cert: pubLen=${testMasterPublic.length}, sigLen=${signatureDer.length}, sigDer=${bytesToHex(signatureDer.slice(0, 6))}...`);

        const certificate = new Uint8Array([
            testMasterPublic.length,
            ...testMasterPublic,
            signatureDer.length,
            ...signatureDer
        ]);

        apdu = new Uint8Array([0xe0, 0x51, 0x00, 0x00, certificate.length, ...certificate]);
        console.log(`SCP: VALIDATE_CERT master APDU len=${apdu.length}, cert len=${certificate.length}`);
        result = await rawExchange(apdu);
        
        if (result.sw !== 0x9000) {
            console.warn(`SCP: Master cert SW=0x${result.sw.toString(16)} (continuing - sideload mode)`);
        } else {
            console.log('SCP: Master cert accepted');
        }
    }

    // --- Step 4: VALIDATE_CERT (ephemeral certificate, P1=0x80) ---
    // Python: apdu = bytearray([0xE0, 0x51, 0x80, 0x00]) + bytearray([len(certificate)]) + certificate
    const ephemeralPrivate = new PrivateKey();
    const ephemeralPublic = ephemeralPrivate.pubkey.serialize(false);
    console.log(`SCP: Ephemeral pub=${bytesToHex(ephemeralPublic).slice(0, 16)}...`);

    // Sign: 0x11 || nonce || deviceNonce || ephemeralPublic
    const ephDataToSign = new Uint8Array([0x11, ...nonce, ...deviceNonce, ...ephemeralPublic]);
    const ephSignature = testMaster.ecdsaSign(ephDataToSign);
    const ephSignatureDer = testMaster.ecdsaSerialize(ephSignature);

    const ephCertificate = new Uint8Array([
        ephemeralPublic.length,
        ...ephemeralPublic,
        ephSignatureDer.length,
        ...ephSignatureDer
    ]);

    // P1=0x80 = last certificate
    apdu = new Uint8Array([0xe0, 0x51, 0x80, 0x00, ephCertificate.length, ...ephCertificate]);
    console.log(`SCP: VALIDATE_CERT ephemeral APDU len=${apdu.length}`);
    result = await rawExchange(apdu);
    if (result.sw !== 0x9000) {
        console.warn(`SCP: Ephemeral cert SW=0x${result.sw.toString(16)} (continuing)`);
    }

    // --- Step 5: GET_CERT (walk device certificates) ---
    // Python: dongle.exchange(bytearray.fromhex('E052000000')) for index 0
    //         dongle.exchange(bytearray.fromhex('E052800000')) for index 1
    let lastDevPubKey = new PublicKey(testMasterPublic, true);
    let devicePublicKey = null;

    for (let index = 0; index < 2; index++) {
        const p1 = index === 0 ? 0x00 : 0x80;
        const certApdu = new Uint8Array([0xe0, 0x52, p1, 0x00, 0x00]);
        const certResult = await rawExchange(certApdu);
        
        if (certResult.sw !== 0x9000) {
            console.warn(`SCP: GET_CERT[${index}] SW=0x${certResult.sw.toString(16)}`);
        }

        const certResponse = certResult.data;
        if (!certResponse || certResponse.length === 0) {
            console.warn(`SCP: GET_CERT[${index}] empty response - skipping`);
            continue;
        }

        console.log(`SCP: GET_CERT[${index}] ${certResponse.length} bytes`);

        // Parse certificate: header(len+data) || pubkey(len+data) || sig(len+data)
        let offset = 0;
        const headerLen = certResponse[offset++];
        const certHeader = certResponse.slice(offset, offset + headerLen);
        offset += headerLen;

        const pubKeyLen = certResponse[offset++];
        const certPublicKey = certResponse.slice(offset, offset + pubKeyLen);
        offset += pubKeyLen;

        const sigLen = certResponse[offset++];
        const certSignatureArray = certResponse.slice(offset, offset + sigLen);

        // Verify certificate signature
        const certSignature = lastDevPubKey.ecdsaDeserialize(certSignatureArray);

        let certSignedData;
        if (index === 0) {
            devicePublicKey = certPublicKey;
            certSignedData = new Uint8Array([0x02, ...certHeader, ...certPublicKey]);
        } else {
            certSignedData = new Uint8Array([0x12, ...deviceNonce, ...nonce, ...certPublicKey]);
        }

        const verified = lastDevPubKey.ecdsaVerify(certSignedData, certSignature);
        if (!verified) {
            if (index === 0) {
                console.log('SCP: Broken certificate chain - loading from user key');
            } else {
                throw new Error('SCP: Broken certificate chain at device ephemeral cert');
            }
        } else {
            console.log(`SCP: Device cert[${index}] verified`);
        }

        lastDevPubKey = new PublicKey(certPublicKey, true);
        console.log(`SCP: GET_CERT[${index}] pubKey=${bytesToHex(certPublicKey).slice(0, 16)}... (${certPublicKey.length}B)`);
    }

    // --- Step 6: COMMIT ---
    // Python: dongle.exchange(bytearray.fromhex('E053000000'))
    result = await rawExchange(new Uint8Array([0xe0, 0x53, 0x00, 0x00, 0x00]));
    if (result.sw !== 0x9000) {
        console.warn(`SCP: COMMIT SW=0x${result.sw.toString(16)}`);
    }

    // --- Step 7: ECDH shared secret ---
    const ephemeralPrivBytes = hexToBytes(ephemeralPrivate.serialize());
    console.log(`SCP: ECDH devPub=${bytesToHex(lastDevPubKey.serialize(false)).slice(0, 16)}...`);
    const secret = lastDevPubKey.ecdh(ephemeralPrivBytes);
    console.log(`SCP: ECDH secret=${bytesToHex(secret)}`);
    console.log('SCP: Secure channel established');

    // Return format depends on SCP version
    if (ecdhSecretFormat === 1 || (targetId & 0xf) === 0x2) {
        // SCP v2: first 16 bytes
        return secret.slice(0, 16);
    } else if ((targetId & 0xf) >= 0x3) {
        // SCP v3: full secret + device public key for key derivation
        return { ecdh_secret: secret, devicePublicKey };
    }

    return secret.slice(0, 16);
}

// Legacy SCP v1 (pre Nano S 1.4) - kept for completeness
export async function getDeployedSecretV1(dongle, masterPrivate, targetId) {
    const testMaster = new PrivateKey(masterPrivate);
    const testMasterPublic = testMaster.pubkey.serialize(false);
    const targetIdBytes = uint32ToBytes(targetId);

    let apdu = new Uint8Array([0xe0, 0x04, 0x00, 0x00, targetIdBytes.length, ...targetIdBytes]);
    await dongle.exchange(apdu);

    const nonce = randomBytes(8);
    apdu = new Uint8Array([0xe0, 0x50, 0x00, 0x00, nonce.length, ...nonce]);
    const batchInfo = await dongle.exchange(apdu);
    const deviceNonce = batchInfo.slice(4, 12);

    const dataToSign = new Uint8Array([0x01, ...testMasterPublic]);
    const signature = testMaster.ecdsaSign(dataToSign);
    const signatureDer = testMaster.ecdsaSerialize(signature);

    const certificate = new Uint8Array([
        testMasterPublic.length, ...testMasterPublic,
        signatureDer.length, ...signatureDer
    ]);
    
    const ephemeralPrivate = new PrivateKey();
    const ephemeralPublic = ephemeralPrivate.pubkey.serialize(false);

    const ephDataToSign = new Uint8Array([0x11, ...nonce, ...deviceNonce, ...ephemeralPublic]);
    const ephSig = testMaster.ecdsaSign(ephDataToSign);
    const ephSigDer = testMaster.ecdsaSerialize(ephSig);

    const fullCert = new Uint8Array([
        ...certificate,
        ephemeralPublic.length, ...ephemeralPublic,
        ephSigDer.length, ...ephSigDer
    ]);

    apdu = new Uint8Array([0xe0, 0x51, 0x00, 0x00, fullCert.length, ...fullCert]);
    await dongle.exchange(apdu);

    let lastPubKey = new PublicKey(testMasterPublic, true);
    let index = 0;
    while (true) {
        const certResponse = await dongle.exchange(new Uint8Array([0xe0, 0x52, 0x00, 0x00, 0x00]));
        if (certResponse.length === 0) break;

        let offset = 0;
        const headerLen = certResponse[offset++];
        offset += headerLen;
        const pubKeyLen = certResponse[offset++];
        const certPublicKey = certResponse.slice(offset, offset + pubKeyLen);
        offset += pubKeyLen;

        lastPubKey = new PublicKey(certPublicKey, true);
        index++;
        if (index >= 2) break;
    }

    await dongle.exchange(new Uint8Array([0xe0, 0x53, 0x00, 0x00, 0x00]));

    const ephemeralPrivBytes = hexToBytes(ephemeralPrivate.serialize());
    const secret = lastPubKey.ecdh(ephemeralPrivBytes);
    return secret.slice(0, 16);
}

export default { getDeployedSecretV2, getDeployedSecretV1 };
