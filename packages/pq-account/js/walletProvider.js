import { EthereumProvider } from '@walletconnect/ethereum-provider';

const WALLETCONNECT_PROJECT_ID = '9df9bc4cfc1db06d40cc7bdad20e199f';

const CHAIN_CONFIG = {
    sepolia:         { id: 11155111, hex: '0xaa36a7', rpc: 'https://eth-sepolia-testnet.api.pocket.network' },
    arbitrumSepolia: { id: 421614,   hex: '0x66eee',  rpc: 'https://sepolia-rollup.arbitrum.io/rpc' },
    baseSepolia:     { id: 84532,    hex: '0x14a34',  rpc: 'https://sepolia.base.org' },
};

const WALLET_DEEPLINKS = {
    rabby:    (uri) => `https://rabby.io/wc?uri=${encodeURIComponent(uri)}`,
    metamask: (uri) => `https://metamask.app.link/wc?uri=${encodeURIComponent(uri)}`,
    any:      (uri) => uri, // raw wc: URI — Android picks the default handler
};

let wcProvider = null;

function isMobile() {
    return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
}

/**
 * Show a bottom-sheet popup to pick a wallet, then deep-link with the WC URI.
 * Returns a promise that resolves when the user picks a wallet.
 */
function showWalletPicker(wcUri) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.id = 'wallet-popup-overlay';
        overlay.innerHTML = `
            <div id="wallet-popup">
                <p>Connect your wallet</p>
                <button class="wallet-btn" data-wallet="any">Open wallet (auto-detect)</button>
                <button class="wallet-btn" data-wallet="rabby">Rabby</button>
                <button class="wallet-btn" data-wallet="metamask">MetaMask</button>
                <button class="wallet-close" id="wallet-popup-close">Cancel</button>
            </div>
        `;

        const style = document.createElement('style');
        style.textContent = `
            #wallet-popup-overlay {
                position: fixed; inset: 0; z-index: 9999;
                background: rgba(0,0,0,0.5);
                display: flex; align-items: flex-end; justify-content: center;
                animation: wpFadeIn .2s;
            }
            #wallet-popup {
                background: #1a1a2e; color: #eee;
                border-radius: 16px 16px 0 0;
                padding: 1.5rem; width: 100%; max-width: 400px;
                text-align: center;
                animation: wpSlideUp .25s ease-out;
            }
            #wallet-popup p {
                margin: 0 0 1rem; font-size: 1rem; font-weight: 600;
            }
            #wallet-popup .wallet-btn {
                display: block; width: 100%; padding: 0.85rem; margin: 0.5rem 0;
                border-radius: 10px; background: #2d2d44; color: #fff;
                border: none; font-size: 0.95rem; font-weight: 500; cursor: pointer;
            }
            #wallet-popup .wallet-btn:active { background: #3d3d5c; }
            #wallet-popup .wallet-close {
                margin-top: 0.75rem; background: none; border: none;
                color: #888; font-size: 0.85rem; cursor: pointer;
            }
            @keyframes wpFadeIn { from { opacity: 0 } to { opacity: 1 } }
            @keyframes wpSlideUp { from { transform: translateY(100%) } to { transform: translateY(0) } }
        `;
        document.head.appendChild(style);
        document.body.appendChild(overlay);

        function cleanup() {
            overlay.remove();
            style.remove();
        }

        overlay.querySelectorAll('.wallet-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const wallet = btn.dataset.wallet;
                const deepLink = WALLET_DEEPLINKS[wallet];
                if (deepLink) {
                    window.location.href = deepLink(wcUri);
                }
                cleanup();
                resolve(wallet);
            });
        });

        document.getElementById('wallet-popup-close').addEventListener('click', () => {
            cleanup();
            resolve(null);
        });
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                cleanup();
                resolve(null);
            }
        });
    });
}

/**
 * Returns an EIP-1193 provider.
 * Uses window.ethereum if available, otherwise WalletConnect with mobile deep-link.
 */
export async function getProvider(networkKey) {
    if (window.ethereum) {
        return { provider: window.ethereum, isWalletConnect: false };
    }

    const chain = CHAIN_CONFIG[networkKey];
    if (!chain) throw new Error('Unknown network: ' + networkKey);

    if (wcProvider) {
        try { await wcProvider.disconnect(); } catch (_) {}
        wcProvider = null;
    }

    console.log('Initializing WalletConnect…');

    wcProvider = await EthereumProvider.init({
        projectId: WALLETCONNECT_PROJECT_ID,
        chains: [chain.id],
        showQrModal: !isMobile(),  // QR on desktop, custom deep-link on mobile
        rpcMap: { [chain.id]: chain.rpc },
        metadata: {
            name: 'ZKNOX PQ Account',
            description: 'Post-Quantum ERC-4337 Account',
            url: window.location.origin,
            icons: [],
        },
    });

    if (isMobile()) {
        // On mobile: capture the WC URI and deep-link to the wallet app
        const uriPromise = new Promise((resolve) => {
            wcProvider.on('display_uri', (uri) => {
                resolve(uri);
            });
        });

        // Start connection (non-blocking — generates the URI)
        const connectPromise = wcProvider.connect();

        const uri = await uriPromise;
        console.log('Opening wallet app…');

        const picked = await showWalletPicker(uri);
        if (!picked) {
            throw new Error('Wallet connection cancelled.');
        }

        console.log('Waiting for wallet approval…');
        await connectPromise;
    } else {
        // Desktop: the built-in QR modal handles it
        await wcProvider.connect();
    }

    console.log('Wallet connected.');
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
