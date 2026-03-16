const CHAIN_CONFIG = {
    sepolia:         { id: 11155111, hex: '0xaa36a7', rpc: 'https://eth-sepolia-testnet.api.pocket.network' },
    arbitrumSepolia: { id: 421614,   hex: '0x66eee',  rpc: 'https://sepolia-rollup.arbitrum.io/rpc' },
    baseSepolia:     { id: 84532,    hex: '0x14a34',  rpc: 'https://sepolia.base.org' },
};

function isMobile() {
    return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
}

function showWalletPopup() {
    const dappUrl = window.location.href;

    const overlay = document.createElement('div');
    overlay.id = 'wallet-popup-overlay';
    overlay.innerHTML = `
        <div id="wallet-popup">
            <p>Open in wallet app</p>
            <a class="wallet-btn" href="rabby://open?url=${encodeURIComponent(dappUrl)}">
                Rabby
            </a>
            <a class="wallet-btn" href="https://metamask.app.link/dapp/${dappUrl.replace(/^https?:\/\//, '')}">
                MetaMask
            </a>
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
            display: block; padding: 0.85rem; margin: 0.5rem 0;
            border-radius: 10px; background: #2d2d44; color: #fff;
            text-decoration: none; font-size: 0.95rem; font-weight: 500;
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

    document.getElementById('wallet-popup-close').addEventListener('click', () => {
        overlay.remove();
        style.remove();
    });
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            overlay.remove();
            style.remove();
        }
    });
}

/**
 * Returns an EIP-1193 provider.
 * Uses window.ethereum if available, otherwise shows wallet redirect on mobile.
 */
export async function getProvider(networkKey) {
    if (window.ethereum) {
        return { provider: window.ethereum, isWalletConnect: false };
    }

    const chain = CHAIN_CONFIG[networkKey];
    if (!chain) throw new Error('Unknown network: ' + networkKey);

    if (isMobile()) {
        showWalletPopup();
        throw new Error('Tap a wallet to open this page in its built-in browser.');
    }

    throw new Error('No wallet detected. Install MetaMask or Rabby.');
}

export function getChainHex(networkKey) {
    return CHAIN_CONFIG[networkKey]?.hex;
}

export async function disconnectWC() {
    // no-op
}
