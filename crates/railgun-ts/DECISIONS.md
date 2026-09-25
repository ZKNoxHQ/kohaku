# railgun-ts (ZKNOX fork) — décisions

## ADR-001 — Page wallet statique : aucun relais, broadcasters par le nœud Waku Rust

Contexte : la page de test de Simon (4337 + Ledger WebUSB) passait par un serveur de dev qui
relayait `/poi` vers ppoi.fdi.network. Ce nœud publie une adresse IPv6 (AAAA, via un CNAME vers
l'instance Scaleway) qui refuse les connexions sur le port 443, constaté le 2026-09-25 : un réseau
double pile retombe sur l'IPv4, un réseau IPv6 seul sans CLAT (NAT64/DNS64) ne peut pas l'atteindre,
l'AAAA empêchant la synthèse d'une adresse NAT64.

Décision :
- la page (`web/index.html`) appelle le nœud POI de `ChainConfig` directement, ou celui saisi dans
  le champ « POI node » (`withPoiEndpoint`) ; `dev-server.py`,
  `serve.sh` (relais et tunnel) et `test-wallet.html` sont retirés ; `build-web.sh` produit des
  fichiers statiques (cargo + wasm-bindgen, wasm-opt si présent) ;
- transport legacy dans le navigateur : `Broadcasters` (client `railgun-broadcaster` sur
  `LightNodeTransport`, soit `waku-light` en wasm sur le WebSocket du navigateur), jamais js-waku ;
  `RailgunProvider.sendViaBroadcaster` reprend le déroulé du moteur natif du wallet : bande des
  signataires de confiance Railway, tirage parmi les offres proches de la moins chère, plafond en
  multiple du coût du gas, convergence du fee sur deux estimations à preuve factice (sans
  signature), une seule preuve réelle (une signature Ledger), POI pré-transaction, requête scellée ;
- avant la synchronisation, la page vérifie que le réseau atteint le nœud POI (`fetch` en
  `no-cors`, 10 s) ; sinon elle s'arrête sur un message qui explique le cas IPv6 seul et propose un
  réseau avec IPv4 (Wi-Fi) ou un autre nœud, au lieu d'une erreur réseau brute au milieu du sync ;
- Ledger en WebUSB ou en Bluetooth (`connectLedgerWebUsb` / `connectLedgerWebBle`) ;
- le site regroupe deux pages (`web-site/build.sh`) : `wallet/` et `viewer/` (Dr Rail).

Conséquences : tout hébergement statique convient (GitHub Pages, Netlify Drop). Tant que FDI ne
sert pas l'IPv6 (`listen [::]:443`) ou ne retire pas l'AAAA, les statuts et preuves POI échouent sur
les réseaux IPv6 seuls sans CLAT ; recours côté page : un autre nœud POI dans le champ prévu. SDK : accesseur `RailgunProvider::eth_provider()` ajouté pour le prix du gas et les
estimations.
