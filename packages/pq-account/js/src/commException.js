/**
 * Ledger Communication Exception
 * Port of ledgerblue/commException.py
 */

export class CommException extends Error {
    constructor(message, sw = 0x6f00, data = null) {
        super(message);
        this.name = 'CommException';
        this.sw = sw;
        this.data = data;
    }

    toString() {
        return `Exception: ${this.message}`;
    }
}

/**
 * Get possible error cause from status word
 * @param {number} sw - Status word
 * @returns {string}
 */
export function getPossibleErrorCause(sw) {
    const causeMap = {
        0x6982: "Have you uninstalled the existing CA with resetCustomCA first?",
        0x6985: "Condition of use not satisfied (denied by the user?)",
        0x6a84: "Not enough space?",
        0x6a85: "Not enough space?",
        0x6a83: "Maybe this app requires a library to be installed first?",
        0x6484: "Are you using the correct targetId?",
        0x6d00: "Unexpected state of device: verify that the right application is opened?",
        0x6e00: "Unexpected state of device: verify that the right application is opened?",
        0x6e01: "CLA not supported - wrong APDU format after SCP?",
        0x5515: "Did you unlock the device?",
        0x6814: "Unexpected target device: verify that you are using the right device?",
        0x511f: "OS version incompatible with SDK used to build the app",
        0x5120: "Sideload is not supported on Nano X",
        0x6511: "Device is not in Recovery Mode - boot while holding button",
        0x6512: "Device locked or not in right state",
        0x5707: "SCP certificate validation failed - check custom CA installation",
        0x6603: "SCP mutual authentication failed - certificate chain rejected",
        0x5214: "Custom CA setup rejected - device may not be in onboarding state",
        0x6615: "SCP encryption error - key mismatch or corrupted data",
    };

    return causeMap[sw] || `Unknown reason (0x${sw.toString(16)})`;
}

export default CommException;
