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
    const strippedUrl = dappUrl.replace(/^https?:\/\//, '');

    const overlay = document.createElement('div');
    overlay.id = 'wallet-popup-overlay';
    overlay.innerHTML = `
        <div id="wallet-popup">
            <p>Open this page in your wallet's browser</p>
            <div class="wallet-url-box">
                <input type="text" id="wallet-url" value="${dappUrl}" readonly>
                <button id="wallet-copy-btn">Copy</button>
            </div>
            <small style="color:#888; display:block; margin:0.5rem 0 1rem;">
                Copy the URL, open your wallet app, go to its DApp browser and paste it.
            </small>
            <a class="wallet-btn" href="https://rabby.io/dapp?url=${encodeURIComponent(dappUrl)}">
                Open in Rabby
            </a>
            <a class="wallet-btn" href="https://metamask.app.link/dapp/${strippedUrl}">
                Open in MetaMask
            </a>
            <button class="wallet-close" id="wallet-popup-close">Close</button>
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
        .wallet-url-box {
            display: flex; gap: 0.5rem; margin: 0.5rem 0;
        }
        .wallet-url-box input {
            flex: 1; padding: 0.5rem; border-radius: 8px;
            border: 1px solid #444; background: #111; color: #fff;
            font-size: 0.8rem; min-width: 0;
        }
        .wallet-url-box button {
            padding: 0.5rem 0.75rem; border-radius: 8px;
            background: #4a4a6a; color: #fff; border: none;
            font-size: 0.8rem; cursor: pointer; white-space: nowrap;
        }
        #wallet-popup .wallet-close {
            margin-top: 0.75rem; background: none; border: none;
            color: #888; font-size: 0.85rem; cursor: pointer;
        }
        @keyframes wpFadeIn { from { opacity: 0 } to { opacity: 1 } }
        @keyframes wpSlideUp { from { transform: translateY(100%) } to { transform: translateY(0) } }
    `;
    document.head.appendChild(style);
    document.body.appendChild(overlay);

    document.getElementById('wallet-copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(dappUrl).then(() => {
            document.getElementById('wallet-copy-btn').textContent = 'Copied!';
        });
    });

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
