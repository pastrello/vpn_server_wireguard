document.addEventListener("submit", (event) => {
    const form = event.target;
    const message = form.dataset.confirm;

    if (message && !window.confirm(message)) {
        event.preventDefault();
    }
});

document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy-target]");
    if (!button) return;

    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;

    try {
        await navigator.clipboard.writeText(target.innerText);
        const original = button.innerText;
        button.innerText = "Copiado";
        setTimeout(() => button.innerText = original, 1600);
    } catch (_) {
        window.alert("Não foi possível copiar automaticamente.");
    }
});

function setStatusBadge(element, state, label) {
    if (!element) return;
    element.className = `badge badge-${state}`;
    element.textContent = label;
}

function updateHealth(health) {
    const values = {
        interface_up: health.interface_up ? "ONLINE" : "OFFLINE",
        listen_port: health.listen_port ? `UDP ${health.listen_port}` : "—",
        nft_table: health.nft_table ? "OK" : "FALHA",
        firewalld: health.firewalld ? "ATIVO" : "INATIVO",
        ip_forward: health.ip_forward ? "ATIVO" : "INATIVO",
        route_count: String(health.route_count ?? 0),
    };

    for (const [key, value] of Object.entries(values)) {
        const node = document.querySelector(`[data-health="${key}"]`);
        if (node) node.textContent = value;
    }
}

function updateCounts(counts) {
    for (const [key, value] of Object.entries(counts)) {
        document.querySelectorAll(`[data-count="${key}"]`).forEach((node) => {
            node.textContent = value;
        });
    }
}

function updateSites(sites) {
    for (const [siteId, counts] of Object.entries(sites || {})) {
        const card = document.querySelector(`[data-site-id="${siteId}"]`);
        if (!card) continue;

        for (const state of ["online", "idle", "offline", "never"]) {
            const node = card.querySelector(`[data-site-count="${state}"]`);
            if (node) node.textContent = counts[state] ?? 0;
        }

        const badge = card.querySelector("[data-site-main-state]");
        if (!badge) continue;

        if (counts.online) {
            setStatusBadge(badge, "online", `${counts.online} online`);
        } else if (counts.idle) {
            setStatusBadge(badge, "idle", `${counts.idle} idle`);
        } else if (counts.offline) {
            setStatusBadge(badge, "offline", "offline");
        } else {
            setStatusBadge(badge, "never", "sem conexão");
        }
    }
}

function updatePeerRows(peers) {
    const rows = document.querySelectorAll("[data-peer-key]");
    const peerMap = new Map((peers || []).map((peer) => [peer.key, peer]));

    const statusBody = document.querySelector("[data-status-body]");
    if (statusBody && rows.length !== (peers || []).length) {
        window.location.reload();
        return;
    }

    rows.forEach((row) => {
        const peer = peerMap.get(row.dataset.peerKey);
        if (!peer) return;

        setStatusBadge(
            row.querySelector('[data-field="state"]'),
            peer.state,
            peer.state_label,
        );

        const fields = {
            endpoint: peer.endpoint,
            handshake: peer.handshake,
            rx: peer.rx,
            tx: peer.tx,
        };

        for (const [field, value] of Object.entries(fields)) {
            const node = row.querySelector(`[data-field="${field}"]`);
            if (node) node.textContent = value;
        }
    });

    if (statusBody) {
        for (const peer of peers || []) {
            const row = document.querySelector(`[data-peer-key="${peer.key}"]`);
            if (row) statusBody.appendChild(row);
        }
    }
}

async function refreshLiveStatus(endpoint) {
    try {
        const response = await fetch(endpoint, {
            headers: { "Accept": "application/json" },
            cache: "no-store",
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        updateHealth(data.health || {});
        updateCounts(data.counts || {});
        updateSites(data.sites || {});
        updatePeerRows(data.peers || []);

        const stamp = document.querySelector("[data-last-refresh]");
        if (stamp) {
            stamp.textContent = new Date().toLocaleTimeString();
        }
    } catch (error) {
        const stamp = document.querySelector("[data-last-refresh]");
        if (stamp) stamp.textContent = "falha ao atualizar";
        console.error("VPNHub status refresh failed", error);
    }
}

const liveRoot = document.querySelector("[data-status-endpoint]");
if (liveRoot) {
    const endpoint = liveRoot.dataset.statusEndpoint;
    const interval = Number(liveRoot.dataset.autoRefresh || 30000);
    setInterval(() => refreshLiveStatus(endpoint), interval);
}

const refreshButton = document.querySelector("[data-refresh-status]");
if (refreshButton) {
    refreshButton.addEventListener("click", () => {
        const root = document.querySelector("[data-status-endpoint]");
        if (root) refreshLiveStatus(root.dataset.statusEndpoint);
    });
}
