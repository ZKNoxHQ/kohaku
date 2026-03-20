import EthereumProvider from '@walletconnect/ethereum-provider';

const CHAIN_CONFIG = {
    sepolia:         { id: 11155111, hex: '0xaa36a7', rpc: 'https://eth-sepolia-testnet.api.pocket.network' },
    arbitrumSepolia: { id: 421614,   hex: '0x66eee',  rpc: 'https://sepolia-rollup.arbitrum.io/rpc' },
    baseSepolia:     { id: 84532,    hex: '0x14a34',  rpc: 'https://sepolia.base.org' },
};

// WalletConnect project ID — get one at https://cloud.walletconnect.com
const WC_PROJECT_ID = '0b02d8da0c1b4bc0a09a3bbf7cc54967';

let _wcProvider = null;

/**
 * Returns an EIP-1193 provider.
 * Uses window.ethereum if available, otherwise falls back to WalletConnect.
 */
export async function getProvider(networkKey) {
    // 1. Injected wallet (Rabby, MetaMask extension, or in-app browser)
    if (window.ethereum) {
        return { provider: window.ethereum, isWalletConnect: false };
    }

    const chain = CHAIN_CONFIG[networkKey];
    if (!chain) throw new Error('Unknown network: ' + networkKey);

    // 2. WalletConnect fallback (mobile + desktop without extension)
    console.log('No injected wallet — connecting via WalletConnect…');

    const wcProvider = await EthereumProvider.init({
        projectId: WC_PROJECT_ID,
        chains: [chain.id],
        showQrModal: true,
        rpcMap: Object.fromEntries(
            Object.values(CHAIN_CONFIG).map(c => [c.id, c.rpc])
        ),
        metadata: {
            name: 'PQ Account',
            description: 'Post-quantum ERC-4337 account manager',
            url: window.location.origin,
            icons: [],
        },
    });

    await wcProvider.connect();
    _wcProvider = wcProvider;

    return { provider: wcProvider, isWalletConnect: true };
}

export function getChainHex(networkKey) {
    return CHAIN_CONFIG[networkKey]?.hex;
}

export async function disconnectWC() {
    if (_wcProvider) {
        try { await _wcProvider.disconnect(); } catch (_) {}
        _wcProvider = null;
    }
}
