import { ethers } from 'ethers';

// Etherscan V2 unified endpoint
const ETHERSCAN_API_URL = 'https://api.etherscan.io/v2/api';

const CHAIN_IDS = {
    sepolia:         11155111,
    arbitrumSepolia: 421614,
    baseSepolia:     84532,
};

const COMPILER_VERSION = 'v0.8.30+commit.73712a01';
const CONTRACT_NAME = 'ZKNOX_ERC4337_account';
const OPTIMIZATION_RUNS = 10000;
const EVM_VERSION = 'cancun';

/**
 * Read the factory's immutable values to reconstruct the constructor arguments.
 */
async function getConstructorArgs(factoryContract, preQuantumPubKey, postQuantumPubKey) {
    const entryPoint = await factoryContract.ENTRY_POINT();
    const preQuantumLogic = await factoryContract.PRE_QUANTUM_LOGIC();
    const postQuantumLogic = await factoryContract.POST_QUANTUM_LOGIC();

    // ABI-encode the constructor arguments (address, bytes, bytes, address, address)
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address', 'bytes', 'bytes', 'address', 'address'],
        [entryPoint, preQuantumPubKey, postQuantumPubKey, preQuantumLogic, postQuantumLogic]
    );

    // Remove '0x' prefix — Etherscan expects raw hex
    return encoded.slice(2);
}

/**
 * Verify a deployed account contract on Etherscan (V2 API).
 */
export async function verifyAccountContract(
    contractAddress,
    network,
    apiKey,
    factoryContract,
    preQuantumPubKey,
    postQuantumPubKey
) {
    const chainId = CHAIN_IDS[network];
    if (!chainId) {
        throw new Error('Unsupported network for verification: ' + network);
    }

    console.log('Fetching flattened source code…');
    const sourceResp = await fetch('/ZKNOX_ERC4337_account_flat.sol');
    if (!sourceResp.ok) {
        throw new Error('Could not load flattened source file');
    }
    const sourceCode = await sourceResp.text();

    console.log('Reading constructor arguments from factory…');
    const constructorArgs = await getConstructorArgs(factoryContract, preQuantumPubKey, postQuantumPubKey);
    console.log('Constructor args (first 64 chars): ' + constructorArgs.slice(0, 64) + '…');

    console.log('Submitting verification to ' + network + ' (chainId ' + chainId + ')…');

    const params = new URLSearchParams();
    params.append('apikey', apiKey);
    params.append('module', 'contract');
    params.append('action', 'verifysourcecode');
    params.append('contractaddress', contractAddress);
    params.append('sourceCode', sourceCode);
    params.append('codeformat', 'solidity-single-file');
    params.append('contractname', CONTRACT_NAME);
    params.append('compilerversion', COMPILER_VERSION);
    params.append('optimizationUsed', '1');
    params.append('runs', String(OPTIMIZATION_RUNS));
    params.append('constructorArguements', constructorArgs);  // Etherscan typo is intentional
    params.append('evmversion', EVM_VERSION);
    params.append('licenseType', '3'); // MIT

    const resp = await fetch(ETHERSCAN_API_URL + '?chainid=' + chainId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
    });

    const data = await resp.json();
    console.log('Etherscan response: ' + JSON.stringify(data));

    if (data.status !== '1') {
        throw new Error('Verification submission failed: ' + (data.result || data.message));
    }

    const guid = data.result;
    console.log('Verification submitted (GUID: ' + guid + '). Checking status…');

    // Poll for verification result
    for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 3000));

        const checkUrl = ETHERSCAN_API_URL
            + '?chainid=' + chainId
            + '&module=contract'
            + '&action=checkverifystatus'
            + '&guid=' + guid
            + '&apikey=' + apiKey;

        const checkResp = await fetch(checkUrl);
        const checkData = await checkResp.json();

        if (checkData.result === 'Pending in queue') {
            console.log('Still pending…');
            continue;
        }

        if (checkData.result === 'Pass - Verified') {
            return { success: true, message: 'Contract verified successfully!' };
        }

        if (checkData.result && !checkData.result.includes('Pending')) {
            return { success: false, message: checkData.result };
        }
    }

    return { success: false, message: 'Verification timed out — check Etherscan manually (GUID: ' + guid + ')' };
}
