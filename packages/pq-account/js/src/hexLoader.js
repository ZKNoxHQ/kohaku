/**
 * Hex Loader - Core app loading functionality with SCP encryption
 * Port of ledgerblue/hexLoader.py
 * 
 * Uses Web Crypto API for AES operations (replaces custom AES implementation)
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { PrivateKey } from './ecWrapper.js';

// Constants
const LOAD_SEGMENT_CHUNK_HEADER_LENGTH = 3;
const MIN_PADDING_LENGTH = 1;
const SCP_MAC_LENGTH = 14;

// TLV Tags
export const BOLOS_TAG_APPNAME = 0x01;
export const BOLOS_TAG_APPVERSION = 0x02;
export const BOLOS_TAG_ICON = 0x03;
export const BOLOS_TAG_DERIVEPATH = 0x04;
export const BOLOS_TAG_DATASIZE = 0x05;
export const BOLOS_TAG_DEPENDENCY = 0x06;

// CRC16-CCITT table
const TABLE_CRC16_CCITT = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
];

// ============================================================
// AES operations via Web Crypto API
// ============================================================

/**
 * AES-CBC encrypt without padding (input MUST be 16-byte aligned)
 * Web Crypto always adds PKCS7 padding, so we encrypt and truncate.
 * The first N bytes of output are identical whether or not PKCS7 is appended.
 */
async function aesCbcEncrypt(key, iv, data) {
    if (data.length === 0) return new Uint8Array(0);
    if (data.length % 16 !== 0) {
        throw new Error(`AES-CBC: data length ${data.length} not 16-byte aligned`);
    }
    const cryptoKey = await crypto.subtle.importKey(
        'raw', key, { name: 'AES-CBC' }, false, ['encrypt']
    );
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv }, cryptoKey, data
    );
    // Truncate PKCS7 padding block (Web Crypto adds 16 bytes for block-aligned input)
    return new Uint8Array(encrypted, 0, data.length);
}

/**
 * AES-CBC decrypt without padding
 * We append a valid PKCS7 padding block to make Web Crypto happy, then truncate.
 */
async function aesCbcDecrypt(key, iv, data) {
    if (data.length === 0) return new Uint8Array(0);
    if (data.length % 16 !== 0) {
        throw new Error(`AES-CBC: data length ${data.length} not 16-byte aligned`);
    }
    const cryptoKey = await crypto.subtle.importKey(
        'raw', key, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']
    );
    
    // To decrypt without padding: encrypt a zero block to get the "next" ciphertext block,
    // then append it as PKCS7 padding that Web Crypto will strip.
    // Alternatively: use a trick with CTR mode or just append proper PKCS7 manually.
    
    // Simple approach: add a block of 0x10 bytes (valid PKCS7 for 16-byte block)
    // encrypted with CBC using the last ciphertext block as IV
    const lastBlock = data.slice(-16);
    const paddingPlain = new Uint8Array(16).fill(16); // PKCS7 padding block
    const paddingEncrypted = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: lastBlock }, cryptoKey, paddingPlain
    );
    // paddingEncrypted is 32 bytes (16 encrypted + 16 PKCS7 from Web Crypto)
    // We only need the first 16 bytes
    const paddingBlock = new Uint8Array(paddingEncrypted, 0, 16);
    
    // Append encrypted padding block to our data
    const dataWithPadding = new Uint8Array(data.length + 16);
    dataWithPadding.set(data);
    dataWithPadding.set(paddingBlock, data.length);
    
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv }, cryptoKey, dataWithPadding
    );
    
    // Result includes our data + the 0x10 padding bytes, truncate to original size
    return new Uint8Array(decrypted).slice(0, data.length);
}

// ============================================================
// TLV encoding
// ============================================================

export function encodelv(v) {
    const L = v.length;
    let header;
    if (L < 128) {
        header = new Uint8Array([L]);
    } else if (L < 256) {
        header = new Uint8Array([0x81, L]);
    } else if (L < 65536) {
        header = new Uint8Array([0x82, (L >> 8) & 0xff, L & 0xff]);
    } else {
        throw new Error('Unimplemented LV encoding');
    }
    const result = new Uint8Array(header.length + v.length);
    result.set(header);
    result.set(v, header.length);
    return result;
}

export function encodetlv(t, v) {
    const L = v.length;
    let header;
    if (L < 128) {
        header = new Uint8Array([t, L]);
    } else if (L < 256) {
        header = new Uint8Array([t, 0x81, L]);
    } else if (L < 65536) {
        header = new Uint8Array([t, 0x82, (L >> 8) & 0xff, L & 0xff]);
    } else {
        throw new Error('Unimplemented TLV encoding');
    }
    const result = new Uint8Array(header.length + v.length);
    result.set(header);
    result.set(v, header.length);
    return result;
}

// ============================================================
// HexLoader class
// ============================================================

export class HexLoader {
    /**
     * @param {object} card - Transport object with exchange() method
     * @param {number} cla - Command class byte (default 0xE0)
     * @param {boolean} secure - Enable SCP encryption
     * @param {object|Uint8Array} mutauthResult - Result from getDeployedSecretV2
     * @param {boolean} relative - Use relative addressing
     * @param {number|null} cleardataBlockLen - Block length for clear data
     * @param {boolean} scpv3 - Use SCP v3 format (explicit)
     */
    constructor(card, cla = 0xe0, secure = false, mutauthResult = null, relative = true, cleardataBlockLen = null, scpv3 = false) {
        this.card = card;
        this.cla = cla;
        this.secure = secure;
        this.createappParams = null;
        this.createpackParams = null;
        this.scpv3 = scpv3;
        
        // Max MTU
        this.maxMtu = 0xfe;
        if (this.card !== null && this.card.apduMaxDataSize) {
            this.maxMtu = Math.min(this.maxMtu, this.card.apduMaxDataSize());
        }
        
        this.scpVersion = 2;
        this.key = mutauthResult;
        this.iv = new Uint8Array(16); // All zeros
        this.relative = relative;
        
        this.cleardataBlockLen = cleardataBlockLen;
        if (this.cleardataBlockLen !== null && this.card !== null && this.card.apduMaxDataSize) {
            this.cleardataBlockLen = Math.min(this.cleardataBlockLen, this.card.apduMaxDataSize());
        }
        
        if (scpv3) {
            this.scpEncKey = this._scpDeriveKey(mutauthResult, 0);
            this.scpVersion = 3;
            if (this.card !== null && this.card.apduMaxDataSize) {
                this.maxMtu = Math.min(0xfe, this.card.apduMaxDataSize() & 0xf0);
            }
            return;
        }
        
        // SCP V3 with object result (Nano S Plus and newer)
        // Key derivation: di = sha256(keyIndex || retry || ecdh_secret)
        //                 Pi = di * G
        //                 ki = sha256(Pi)[0:16]
        if (mutauthResult && typeof mutauthResult === 'object' && mutauthResult.ecdh_secret) {
            const ecdhSecret = mutauthResult.ecdh_secret;
            
            this.scpEncKey = this._scpDeriveKeyV3(ecdhSecret, 0).slice(0, 16);
            this.scpMacKey = this._scpDeriveKeyV3(ecdhSecret, 1).slice(0, 16);
            
            this.scpEncIv = new Uint8Array(16);
            this.scpMacIv = new Uint8Array(16);
            
            this.scpVersion = 3;
            this.maxMtu = 0xfe;
            if (this.card !== null && this.card.apduMaxDataSize) {
                this.maxMtu = Math.min(this.maxMtu, this.card.apduMaxDataSize() & 0xf0);
            }
            
            console.log(`SCP v3: encKey=${bytesToHex(this.scpEncKey)}, macKey=${bytesToHex(this.scpMacKey)}, maxMtu=${this.maxMtu}`);
        }
    }
    
    /**
     * SCP v3 key derivation (SHA256 + EC point method)
     */
    _scpDeriveKeyV3(ecdhSecret, keyIndex) {
        const SECP256K1_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        let retry = 0;
        
        console.log(`_scpDeriveKeyV3: keyIndex=${keyIndex}, ecdhSecret=${bytesToHex(ecdhSecret)}`);
        
        while (true) {
            const data = new Uint8Array(5 + ecdhSecret.length);
            data[0] = (keyIndex >> 24) & 0xff;
            data[1] = (keyIndex >> 16) & 0xff;
            data[2] = (keyIndex >> 8) & 0xff;
            data[3] = keyIndex & 0xff;
            data[4] = retry;
            data.set(ecdhSecret, 5);
            
            const di = sha256(data);
            const diBigInt = bytesToBigInt(di);
            
            if (diBigInt < SECP256K1_ORDER) {
                const privkey = new PrivateKey(di);
                const Pi = privkey.pubkey.serialize(false); // Uncompressed
                const ki = sha256(Pi);
                console.log(`_scpDeriveKeyV3[${keyIndex}]: di=${bytesToHex(di)}, Pi[0:8]=${bytesToHex(Pi.slice(0,8))}, ki[0:16]=${bytesToHex(ki.slice(0,16))}`);
                return ki;
            }
            
            retry++;
            if (retry > 100) throw new Error('Key derivation failed after 100 retries');
        }
    }

    /**
     * CRC16-CCITT
     */
    crc16(data) {
        let crc = 0xffff;
        for (let i = 0; i < data.length; i++) {
            const b = (data[i] ^ ((crc >> 8) & 0xff)) & 0xff;
            crc = (TABLE_CRC16_CCITT[b] ^ (crc << 8)) & 0xffff;
        }
        return crc;
    }

    /**
     * Exchange APDU with SCP encryption
     */
    async exchange(cla, ins, p1, p2, data) {
        const wrappedData = await this.scpWrap(data);
        
        const apdu = new Uint8Array(5 + wrappedData.length);
        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = wrappedData.length;
        apdu.set(wrappedData, 5);
        
        console.log(`HexLoader.exchange: APDU=${bytesToHex(apdu)} (${apdu.length}B)`);
        
        if (this.card === null) {
            console.log('DRY-RUN: ' + bytesToHex(apdu));
            return new Uint8Array(0);
        }
        
        const response = await this.card.exchange(apdu);
        return this.scpUnwrap(response);
    }

    /**
     * SCP wrap: encrypt + MAC
     * Uses Web Crypto API for AES-CBC operations
     */
    async scpWrap(data) {
        if (!this.secure || data === null || data.length === 0) {
            return data;
        }
        console.log(`scpWrap: plain=${bytesToHex(data)} (${data.length}B)`);
        
        // Pad with 0x80 + zeros to 16-byte boundary
        let paddedLen = data.length + 1;
        while ((paddedLen % 16) !== 0) paddedLen++;
        const paddedData = new Uint8Array(paddedLen);
        paddedData.set(data);
        paddedData[data.length] = 0x80;
        
        if (this.scpVersion === 3) {
            // AES-CBC encrypt
            const encryptedData = await aesCbcEncrypt(this.scpEncKey, this.scpEncIv, paddedData);
            this.scpEncIv = encryptedData.slice(-16);
            
            // MAC: AES-CBC-MAC over encrypted data
            const macData = await aesCbcEncrypt(this.scpMacKey, this.scpMacIv, encryptedData);
            this.scpMacIv = macData.slice(-16);
            
            // Append last 14 bytes of MAC
            const result = new Uint8Array(encryptedData.length + SCP_MAC_LENGTH);
            result.set(encryptedData);
            result.set(this.scpMacIv.slice(-SCP_MAC_LENGTH), encryptedData.length);
            
            console.log(`scpWrap: enc=${bytesToHex(encryptedData)}, mac=${bytesToHex(this.scpMacIv)}, wrapped=${bytesToHex(result)}`);
            return result;
        } else {
            // SCP v2 (no MAC)
            const encryptedData = await aesCbcEncrypt(this.key, this.iv, paddedData);
            this.iv = encryptedData.slice(-16);
            return encryptedData;
        }
    }

    /**
     * SCP unwrap: verify MAC + decrypt
     */
    async scpUnwrap(data) {
        if (!this.secure || data === null || data.length === 0 || data.length === 2) {
            return data;
        }
        
        if (this.scpVersion === 3) {
            const encryptedData = data.slice(0, -SCP_MAC_LENGTH);
            const receivedMac = data.slice(-SCP_MAC_LENGTH);
            
            // Verify MAC
            const macData = await aesCbcEncrypt(this.scpMacKey, this.scpMacIv, encryptedData);
            this.scpMacIv = macData.slice(-16);
            
            const expectedMac = this.scpMacIv.slice(-SCP_MAC_LENGTH);
            if (!arraysEqual(expectedMac, receivedMac)) {
                throw new Error(`SCP: Invalid MAC (expected=${bytesToHex(expectedMac)}, got=${bytesToHex(receivedMac)})`);
            }
            
            // Decrypt
            const decryptedData = await aesCbcDecrypt(this.scpEncKey, this.scpEncIv, encryptedData);
            this.scpEncIv = encryptedData.slice(-16);
            
            // Remove ISO/IEC 9797-1 padding (0x80 + zeros)
            let L = decryptedData.length - 1;
            while (L >= 0 && decryptedData[L] !== 0x80) L--;
            if (L < 0) throw new Error('SCP: Invalid padding in decrypted response');
            
            return decryptedData.slice(0, L);
        } else {
            // SCP v2
            const decryptedData = await aesCbcDecrypt(this.key, this.iv, data);
            
            let L = decryptedData.length - 1;
            while (L >= 0 && decryptedData[L] !== 0x80) L--;
            if (L < 0) throw new Error('SCP: Invalid padding in decrypted response');
            
            this.iv = data.slice(-16);
            return decryptedData.slice(0, L);
        }
    }

    // ============================================================
    // Loader commands
    // ============================================================

    async selectSegment(baseAddress) {
        const data = new Uint8Array(5);
        data[0] = 0x05;
        data[1] = (baseAddress >> 24) & 0xff;
        data[2] = (baseAddress >> 16) & 0xff;
        data[3] = (baseAddress >> 8) & 0xff;
        data[4] = baseAddress & 0xff;
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async loadSegmentChunk(offset, chunk) {
        const data = new Uint8Array(3 + chunk.length);
        data[0] = 0x06;
        data[1] = (offset >> 8) & 0xff;
        data[2] = offset & 0xff;
        data.set(chunk, 3);
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async flushSegment() {
        await this.exchange(this.cla, 0x00, 0x00, 0x00, new Uint8Array([0x07]));
    }

    async crcSegment(offsetSegment, lengthSegment, crcExpected) {
        const data = new Uint8Array(9);
        data[0] = 0x08;
        data[1] = (offsetSegment >> 8) & 0xff;
        data[2] = offsetSegment & 0xff;
        data[3] = (lengthSegment >> 24) & 0xff;
        data[4] = (lengthSegment >> 16) & 0xff;
        data[5] = (lengthSegment >> 8) & 0xff;
        data[6] = lengthSegment & 0xff;
        data[7] = (crcExpected >> 8) & 0xff;
        data[8] = crcExpected & 0xff;
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async boot(bootAddr, signature = null) {
        bootAddr |= 1; // Force Thumb mode
        let data;
        if (signature !== null) {
            data = new Uint8Array(6 + signature.length);
            data[0] = 0x09;
            data[1] = (bootAddr >> 24) & 0xff;
            data[2] = (bootAddr >> 16) & 0xff;
            data[3] = (bootAddr >> 8) & 0xff;
            data[4] = bootAddr & 0xff;
            data[5] = signature.length;
            data.set(signature, 6);
        } else {
            data = new Uint8Array(5);
            data[0] = 0x09;
            data[1] = (bootAddr >> 24) & 0xff;
            data[2] = (bootAddr >> 16) & 0xff;
            data[3] = (bootAddr >> 8) & 0xff;
            data[4] = bootAddr & 0xff;
        }
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async commit(signature = null) {
        let data;
        if (signature !== null) {
            data = new Uint8Array(2 + signature.length);
            data[0] = 0x09;
            data[1] = signature.length;
            data.set(signature, 2);
        } else {
            data = new Uint8Array([0x09]);
        }
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async createAppNoInstallParams(appFlags, appLength, appName, icon = null, path = null, iconOffset = null, iconSize = null, appVersion = null) {
        let dataLen = 1 + 4 + 4 + 1 + appName.length;
        if (iconOffset === null) {
            dataLen += icon !== null ? 1 + icon.length : 1;
        }
        if (path !== null) {
            dataLen += 1 + path.length;
        } else {
            dataLen += 1;
        }
        if (iconOffset !== null) dataLen += 6;
        if (appVersion !== null) dataLen += 1 + appVersion.length;
        
        const data = new Uint8Array(dataLen);
        let offset = 0;
        data[offset++] = 0x0b;
        
        data[offset++] = (appLength >> 24) & 0xff;
        data[offset++] = (appLength >> 16) & 0xff;
        data[offset++] = (appLength >> 8) & 0xff;
        data[offset++] = appLength & 0xff;
        
        data[offset++] = (appFlags >> 24) & 0xff;
        data[offset++] = (appFlags >> 16) & 0xff;
        data[offset++] = (appFlags >> 8) & 0xff;
        data[offset++] = appFlags & 0xff;
        
        data[offset++] = appName.length;
        data.set(appName, offset);
        offset += appName.length;
        
        if (iconOffset === null) {
            if (icon !== null) {
                data[offset++] = icon.length;
                data.set(icon, offset);
                offset += icon.length;
            } else {
                data[offset++] = 0;
            }
        }
        
        if (path !== null) {
            data[offset++] = path.length;
            data.set(path, offset);
            offset += path.length;
        } else {
            data[offset++] = 0;
        }
        
        if (iconOffset !== null) {
            data[offset++] = (iconOffset >> 24) & 0xff;
            data[offset++] = (iconOffset >> 16) & 0xff;
            data[offset++] = (iconOffset >> 8) & 0xff;
            data[offset++] = iconOffset & 0xff;
            data[offset++] = (iconSize >> 8) & 0xff;
            data[offset++] = iconSize & 0xff;
        }
        
        if (appVersion !== null) {
            data[offset++] = appVersion.length;
            data.set(appVersion, offset);
        }
        
        this.createappParams = null;
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async createApp(codeLength, apiLevel = 0, dataLength = 0, installParamsLength = 0, flags = 0, bootOffset = 1) {
        let params;
        if (apiLevel !== -1) {
            // struct.pack('>BIIIII', apiLevel, codeLength, dataLength, installParamsLength, flags, bootOffset)
            params = new Uint8Array(21);
            params[0] = apiLevel;
            putUint32(params, 1, codeLength);
            putUint32(params, 5, dataLength);
            putUint32(params, 9, installParamsLength);
            putUint32(params, 13, flags);
            putUint32(params, 17, bootOffset);
        } else {
            // struct.pack('>IIIII', ...)
            params = new Uint8Array(20);
            putUint32(params, 0, codeLength);
            putUint32(params, 4, dataLength);
            putUint32(params, 8, installParamsLength);
            putUint32(params, 12, flags);
            putUint32(params, 16, bootOffset);
        }
        
        this.createappParams = params;
        
        const data = new Uint8Array(1 + params.length);
        data[0] = 0x0B;
        data.set(params, 1);
        
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async deleteApp(appName) {
        const data = new Uint8Array(2 + appName.length);
        data[0] = 0x0c;
        data[1] = appName.length;
        data.set(appName, 2);
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async deleteAppByHash(appFullHash) {
        if (appFullHash.length !== 32) throw new Error('Invalid hash: sha256 expected');
        const data = new Uint8Array(33);
        data[0] = 0x15;
        data.set(appFullHash, 1);
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    /**
     * Load application data from hex file
     * @returns {Promise<string>} SHA256 hash
     */
    async load(eraseU8, maxLengthPerApdu, hexFile, options = {}) {
        const { reverse = false, doCRC = true, targetId = null, targetVersion = null } = options;
        
        if (maxLengthPerApdu > this.maxMtu) {
            maxLengthPerApdu = this.maxMtu;
        }
        
        let initialAddress = this.relative ? hexFile.minAddr() : 0;
        
        // Hash accumulator
        const hashData = [];
        
        // Hash target info for modern devices
        if (targetId !== null && (targetId & 0xf) > 3) {
            const tv = targetVersion || '';
            const targetData = new Uint8Array(4 + tv.length);
            putUint32(targetData, 0, targetId);
            if (tv.length > 0) {
                targetData.set(new TextEncoder().encode(tv), 4);
            }
            hashData.push(targetData);
        }
        
        if (this.createappParams) {
            hashData.push(this.createappParams);
        }
        
        let areas = hexFile.getAreas();
        if (reverse) areas = [...areas].reverse();
        
        for (const area of areas) {
            const startAddress = area.getStart() - initialAddress;
            const data = area.getData();
            
            if (!this.createpackParams) {
                await this.selectSegment(startAddress);
            }
            if (data.length === 0) continue;
            if (data.length > 0x10000) throw new Error('Invalid data size for loader');
            
            const crc = this.crc16(data);
            let offset = 0;
            let length = data.length;
            
            if (reverse) offset = length;
            
            while (length > 0) {
                let chunkLen;
                if (length > maxLengthPerApdu - LOAD_SEGMENT_CHUNK_HEADER_LENGTH - MIN_PADDING_LENGTH - SCP_MAC_LENGTH) {
                    chunkLen = maxLengthPerApdu - LOAD_SEGMENT_CHUNK_HEADER_LENGTH - MIN_PADDING_LENGTH - SCP_MAC_LENGTH;
                    if ((chunkLen % 16) !== 0) chunkLen -= chunkLen % 16;
                } else {
                    chunkLen = length;
                }
                
                if (this.cleardataBlockLen && (chunkLen % this.cleardataBlockLen)) {
                    if (chunkLen < this.cleardataBlockLen) throw new Error('Cannot transport non-block-aligned data');
                    chunkLen -= chunkLen % this.cleardataBlockLen;
                }
                
                let chunk;
                if (reverse) {
                    chunk = data.slice(offset - chunkLen, offset);
                    await this.loadSegmentChunk(offset - chunkLen, chunk);
                } else {
                    chunk = data.slice(offset, offset + chunkLen);
                    hashData.push(chunk);
                    await this.loadSegmentChunk(offset, chunk);
                }
                
                if (reverse) { offset -= chunkLen; } else { offset += chunkLen; }
                length -= chunkLen;
            }
            
            if (!this.createpackParams) await this.flushSegment();
            if (doCRC) await this.crcSegment(0, data.length, crc);
        }
        
        // Compute final hash
        const totalLen = hashData.reduce((sum, arr) => sum + arr.length, 0);
        const combined = new Uint8Array(totalLen);
        let pos = 0;
        for (const arr of hashData) { combined.set(arr, pos); pos += arr.length; }
        
        return bytesToHex(sha256(combined));
    }

    async run(bootOffset = 1, signature = null) {
        await this.boot(bootOffset, signature);
    }

    async resetCustomCA() {
        await this.exchange(this.cla, 0x00, 0x00, 0x00, new Uint8Array([0x13]));
    }

    async setupCustomCA(name, publicKey) {
        const nameBytes = new TextEncoder().encode(name);
        const data = new Uint8Array(1 + 1 + nameBytes.length + 1 + publicKey.length);
        let offset = 0;
        data[offset++] = 0x12;
        data[offset++] = nameBytes.length;
        data.set(nameBytes, offset); offset += nameBytes.length;
        data[offset++] = publicKey.length;
        data.set(publicKey, offset);
        await this.exchange(this.cla, 0x00, 0x00, 0x00, data);
    }

    async runApp(name) {
        await this.exchange(this.cla, 0xd8, 0x00, 0x00, name);
    }

    async getVersion() {
        const response = await this.exchange(this.cla, 0x00, 0x00, 0x00, new Uint8Array([0x10]));
        return { raw: response };
    }

    async listApp(restart = true) {
        const result = [];
        while (true) {
            const p1 = restart ? 0x00 : 0x01;
            restart = false;
            const response = await this.exchange(this.cla, 0x00, 0x00, 0x00, new Uint8Array([0x0e]));
            if (response.length === 0) break;
            
            let offset = 0;
            while (offset < response.length) {
                const item = {};
                item.flags = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3];
                offset += 4;
                item.hash_code_data = response.slice(offset, offset + 32); offset += 32;
                item.hash = response.slice(offset, offset + 32); offset += 32;
                const nameLen = response[offset++];
                item.name = new TextDecoder().decode(response.slice(offset, offset + nameLen));
                offset += nameLen;
                result.push(item);
            }
        }
        return result;
    }

    async getMemInfo() {
        const response = await this.exchange(this.cla, 0x00, 0x00, 0x00, new Uint8Array([0x11]));
        const r = response;
        return {
            systemSize:       (r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3],
            applicationsSize: (r[4] << 24) | (r[5] << 16) | (r[6] << 8) | r[7],
            freeSize:         (r[8] << 24) | (r[9] << 16) | (r[10] << 8) | r[11],
            usedAppSlots:     (r[12] << 24) | (r[13] << 16) | (r[14] << 8) | r[15],
            totalAppSlots:    (r[16] << 24) | (r[17] << 16) | (r[18] << 8) | r[19],
        };
    }
}

// ============================================================
// Utilities
// ============================================================

function putUint32(buf, offset, value) {
    buf[offset]     = (value >> 24) & 0xff;
    buf[offset + 1] = (value >> 16) & 0xff;
    buf[offset + 2] = (value >> 8) & 0xff;
    buf[offset + 3] = value & 0xff;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBigInt(bytes) {
    let result = 0n;
    for (const byte of bytes) {
        result = (result << 8n) | BigInt(byte);
    }
    return result;
}

function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

export default HexLoader;
