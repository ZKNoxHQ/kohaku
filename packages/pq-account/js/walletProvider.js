import { EthereumProvider } from '@walletconnect/ethereum-provider';

const WALLETCONNECT_PROJECT_ID = '9df9bc4cfc1db06d40cc7bdad20e199f';

const CHAIN_CONFIG = {
    sepolia:         { id: 11155111, hex: '0xaa36a7', rpc: 'https://eth-sepolia-testnet.api.pocket.network' },
    arbitrumSepolia: { id: 421614,   hex: '0x66eee',  rpc: 'https://sepolia-rollup.arbitrum.io/rpc' },
    baseSepolia:     { id: 84532,    hex: '0x14a34',  rpc: 'https://sepolia.base.org' },
};

let wcProvider = null;

/**
 * Returns an EIP-1193 provider.
 * Uses window.ethereum if available (browser extension), otherwise WalletConnect.
 */
export async function getProvider(networkKey) {
    if (window.ethereum) {
        return { provider: window.ethereum, isWalletConnect: false };
    }

    const chain = CHAIN_CONFIG[networkKey];
    if (!chain) throw new Error('Unknown network: ' + networkKey);

    console.log('No browser wallet found — launching WalletConnect…');

    // Disconnect stale session if network changed
    if (wcProvider) {
        try { await wcProvider.disconnect(); } catch (_) {}
        wcProvider = null;
    }

    wcProvider = await EthereumProvider.init({
        projectId: WALLETCONNECT_PROJECT_ID,
        chains: [chain.id],
        showQrModal: true,
        rpcMap: { [chain.id]: chain.rpc },
        metadata: {
            name: 'ZKNOX PQ Account',
            description: 'Post-Quantum ERC-4337 Account',
            url: window.location.origin,
            icons: [],
        },
        qrModalOptions: {
            explorerRecommendedWalletIds: [
                '18388be9ac2d02726dbac9777c96efaac06d744b2f6d580fccdd4127a6d01fd1', // Rabby
                'c57ca95b47569778a828d19178114f4db188b89b763c899ba0be274e97267d96', // MetaMask
            ],
        },
    });

    await wcProvider.connect();
    console.log('WalletConnect session established.');

    return { provider: wcProvider, isWalletConnect: true };
}

export function getChainHex(networkKey) {
    return CHAIN_CONFIG[networkKey]?.hex;
}

export async function disconnectWC() {
    if (wcProvider) {
        try { await wcProvider.disconnect(); } catch (_) {}
        wcProvider = null;
    }
}
