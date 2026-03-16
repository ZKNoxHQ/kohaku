import { createAppKit } from '@reown/appkit';
import { EthersAdapter } from '@reown/appkit-adapter-ethers';

const WALLETCONNECT_PROJECT_ID = '9df9bc4cfc1db06d40cc7bdad20e199f';

const CHAIN_CONFIG = {
    sepolia:         { id: 11155111, hex: '0xaa36a7', name: 'Sepolia',          rpc: 'https://eth-sepolia-testnet.api.pocket.network' },
    arbitrumSepolia: { id: 421614,   hex: '0x66eee',  name: 'Arbitrum Sepolia', rpc: 'https://sepolia-rollup.arbitrum.io/rpc' },
    baseSepolia:     { id: 84532,    hex: '0x14a34',  name: 'Base Sepolia',     rpc: 'https://sepolia.base.org' },
};

// Build Reown-compatible chain definitions
const appKitNetworks = Object.values(CHAIN_CONFIG).map(c => ({
    id: c.id,
    name: c.name,
    nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [c.rpc] } },
    testnet: true,
}));

let modal = null;

function getModal() {
    if (modal) return modal;
    modal = createAppKit({
        adapters: [new EthersAdapter()],
        networks: appKitNetworks,
        defaultNetwork: appKitNetworks[0],
        projectId: WALLETCONNECT_PROJECT_ID,
        metadata: {
            name: 'ZKNOX PQ Account',
            description: 'Post-Quantum ERC-4337 Account',
            url: window.location.origin,
            icons: [],
        },
        featuredWalletIds: [
            '18388be9ac2d02726dbac9777c96efaac06d744b2f6d580fccdd4127a6d01fd1', // Rabby
            'c57ca95b47569778a828d19178114f4db188b89b763c899ba0be274e97267d96', // MetaMask
        ],
    });
    return modal;
}

/**
 * Returns an EIP-1193 provider.
 * Uses window.ethereum if available (browser extension), otherwise opens AppKit modal.
 */
export async function getProvider(networkKey) {
    // Browser extension available — use it directly
    if (window.ethereum) {
        return { provider: window.ethereum, isWalletConnect: false };
    }

    const chain = CHAIN_CONFIG[networkKey];
    if (!chain) throw new Error('Unknown network: ' + networkKey);

    console.log('No browser wallet found — opening wallet selector…');

    const appKit = getModal();

    // Switch to the correct network
    const targetNetwork = appKitNetworks.find(n => n.id === chain.id);
    if (targetNetwork) {
        await appKit.switchNetwork(targetNetwork);
    }

    // Open modal and wait for connection
    await appKit.open();

    const walletProvider = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error('Wallet connection timed out'));
        }, 120000);

        const unsubscribe = appKit.subscribeProviders(state => {
            const eip155 = state?.['eip155'];
            if (eip155) {
                clearTimeout(timeout);
                unsubscribe?.();
                resolve(eip155);
            }
        });
    });

    console.log('Wallet connected via AppKit.');
    return { provider: walletProvider, isWalletConnect: true };
}

export function getChainHex(networkKey) {
    return CHAIN_CONFIG[networkKey]?.hex;
}

export async function disconnectWC() {
    if (modal) {
        try { await modal.disconnect(); } catch (_) {}
    }
}
