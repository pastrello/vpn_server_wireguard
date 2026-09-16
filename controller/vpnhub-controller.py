#!/usr/bin/env python3
from __future__ import annotations
import ipaddress, json, os, shutil, socket, subprocess, tempfile
from pathlib import Path

SOCKET_PATH = os.getenv("CONTROLLER_SOCKET", "/run/vpnhub/controller.sock")
DRY_RUN = os.getenv("WG_DRY_RUN", "true").lower() == "true"
DEFAULT_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
DEFAULT_PRIVATE_KEY = os.getenv("WG_SERVER_PRIVATE_KEY_PATH", "/etc/wireguard/vpnhub-server.key")

class ControllerFailure(RuntimeError):
    pass

def run(cmd, *, input_text=None, check=True):
    proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise ControllerFailure(f"{' '.join(cmd)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc

def interface_exists(interface):
    return run(["ip", "link", "show", "dev", interface], check=False).returncode == 0

def validate_state(payload):
    interface = str(payload.get("interface") or DEFAULT_INTERFACE)
    if not interface.replace("_", "").replace("-", "").isalnum():
        raise ControllerFailure("Nome de interface inválido.")
    listen_port = int(payload.get("listen_port") or 51820)
    if not 1 <= listen_port <= 65535:
        raise ControllerFailure("Porta WireGuard inválida.")
    server_iface = ipaddress.ip_interface(str(payload.get("server_address") or "10.250.0.1/16"))
    vpn_pool = ipaddress.ip_network(str(payload.get("vpn_pool") or server_iface.network), strict=False)
    if server_iface.version != 4 or server_iface.ip not in vpn_pool:
        raise ControllerFailure("WG_SERVER_ADDRESS/VPN_ADDRESS_POOL inválidos.")
    route_protocol = int(payload.get("route_protocol") or 186)
    if not 1 <= route_protocol <= 255:
        raise ControllerFailure("WG_ROUTE_PROTOCOL inválido.")

    peers, keys = [], set()
    for raw in payload.get("peers") or []:
        pub = str(raw.get("public_key") or "").strip()
        if len(pub) < 40 or pub in keys:
            raise ControllerFailure("PublicKey inválida ou duplicada.")
        keys.add(pub)
        allowed = []
        for item in raw.get("allowed_ips") or []:
            net = ipaddress.ip_network(str(item), strict=False)
            if net.version != 4:
                raise ControllerFailure("IPv6 ainda não é suportado.")
            allowed.append(str(net))
        peers.append({
            "kind": str(raw.get("kind") or "site"),
            "site_id": raw.get("site_id"),
            "name": str(raw.get("name") or ""),
            "public_key": pub,
            "preshared_key": str(raw.get("preshared_key") or "").strip() or None,
            "allowed_ips": allowed,
        })

    sites = []
    for raw in payload.get("sites") or []:
        ranges = []
        for item in raw.get("ranges") or []:
            net = ipaddress.ip_network(str(item), strict=False)
            if net.version != 4:
                raise ControllerFailure("IPv6 ainda não é suportado.")
            ranges.append(str(net))
        sites.append({"id": int(raw["id"]), "name": str(raw.get("name") or ""), "ranges": ranges})

    def norm_list(values):
        out = []
        for item in values or []:
            net = ipaddress.ip_network(str(item), strict=False)
            if net.version != 4:
                raise ControllerFailure("IPv6 ainda não é suportado.")
            out.append(str(net))
        return out

    return {
        "interface": interface,
        "listen_port": listen_port,
        "server_address": str(server_iface),
        "vpn_pool": str(vpn_pool),
        "private_key_path": str(payload.get("private_key_path") or DEFAULT_PRIVATE_KEY),
        "route_protocol": route_protocol,
        "peers": peers,
        "sites": sites,
        "admin_addresses": norm_list(payload.get("admin_addresses")),
        "routes": sorted(set(norm_list(payload.get("routes")))),
    }

def check_route_conflicts(state):
    routes = json.loads(run(["ip", "-j", "route", "show"]).stdout or "[]")
    protected = []
    for row in routes:
        dst, dev = row.get("dst"), row.get("dev")
        if not dst or dst == "default" or dev == state["interface"]:
            continue
        try:
            protected.append((ipaddress.ip_network(dst, strict=False), dev or "?"))
        except ValueError:
            pass
    conflicts = []
    for desired in state["routes"]:
        wanted = ipaddress.ip_network(desired)
        for existing, dev in protected:
            if wanted.overlaps(existing):
                conflicts.append(f"{wanted} conflita com rota local {existing} em {dev}")
    if conflicts:
        raise ControllerFailure("Conflito de rota detectado: " + "; ".join(conflicts))

def ensure_kernel_state(state):
    interface = state["interface"]
    if not interface_exists(interface):
        run(["ip", "link", "add", "dev", interface, "type", "wireguard"])
    run(["ip", "address", "replace", state["server_address"], "dev", interface])
    run(["ip", "link", "set", "up", "dev", interface])
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

def render_wg_config(state):
    key_path = Path(state["private_key_path"])
    if not key_path.exists():
        raise ControllerFailure(f"Chave privada do servidor não existe em {key_path}. Execute scripts/bootstrap-wireguard.sh.")
    private_key = key_path.read_text(encoding="utf-8").strip()
    if len(private_key) < 40:
        raise ControllerFailure("Chave privada do servidor inválida.")
    lines = ["[Interface]", f"PrivateKey = {private_key}", f"ListenPort = {state['listen_port']}", ""]
    for peer in state["peers"]:
        lines += ["[Peer]", f"PublicKey = {peer['public_key']}"]
        if peer["preshared_key"]:
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        if peer["allowed_ips"]:
            lines.append("AllowedIPs = " + ", ".join(peer["allowed_ips"]))
        lines.append("")
    return "\n".join(lines)

def apply_wireguard(state):
    content = render_wg_config(state)
    fd, tmp = tempfile.mkstemp(prefix="vpnhub-wg-", suffix=".conf", dir="/run", text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        run(["wg", "syncconf", state["interface"], tmp])
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def apply_routes(state):
    interface, proto = state["interface"], str(state["route_protocol"])
    run(["ip", "route", "flush", "proto", proto, "dev", interface], check=False)
    for network in state["routes"]:
        run(["ip", "route", "replace", network, "dev", interface, "proto", proto])

def nft_set(name, values):
    lines = [f"    set {name} {{", "        type ipv4_addr", "        flags interval"]
    if values:
        lines.append("        elements = { " + ", ".join(values) + " }")
    lines.append("    }")
    return "\n".join(lines)

def render_nftables(state, table_exists):
    interface = state["interface"]
    all_sites = sorted(set(r for s in state["sites"] for r in s["ranges"]))
    body = []
    if table_exists:
        body += ["flush table inet vpnhub", ""]
    body += ["table inet vpnhub {", nft_set("admin_peers", state["admin_addresses"]), "", nft_set("all_sites", all_sites), ""]
    for site in state["sites"]:
        body += [nft_set(f"site_{site['id']}", sorted(set(site["ranges"]))), ""]
    body += [
        "    chain input_guard {",
        "        type filter hook input priority -20; policy accept;",
        f'        iifname "{interface}" ip saddr @admin_peers accept',
        f'        iifname "{interface}" drop',
        "    }", "",
        "    chain forward_guard {",
        "        type filter hook forward priority -20; policy accept;",
        f'        iifname "{interface}" oifname "{interface}" ip saddr @admin_peers ip daddr @all_sites accept',
        f'        iifname "{interface}" oifname "{interface}" ip saddr @all_sites ip daddr @admin_peers ct state established,related accept',
    ]
    for site in state["sites"]:
        n = f"site_{site['id']}"
        body.append(f'        iifname "{interface}" oifname "{interface}" ip saddr @{n} ip daddr @{n} accept')
    body += [f'        iifname "{interface}" drop', f'        oifname "{interface}" drop', "    }", "}", ""]
    return "\n".join(body)

def apply_nftables(state):
    exists = run(["nft", "list", "table", "inet", "vpnhub"], check=False).returncode == 0
    content = render_nftables(state, exists)
    fd, tmp = tempfile.mkstemp(prefix="vpnhub-nft-", suffix=".nft", dir="/run", text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        run(["nft", "-c", "-f", tmp])
        run(["nft", "-f", tmp])
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def configure_firewalld(state):
    warnings = []
    if not shutil.which("firewall-cmd"):
        return warnings
    if run(["systemctl", "is-active", "--quiet", "firewalld"], check=False).returncode != 0:
        return warnings
    default_zone = run(["firewall-cmd", "--get-default-zone"]).stdout.strip() or "public"
    cmds = [
        ["firewall-cmd", "--permanent", f"--zone={default_zone}", f"--add-port={state['listen_port']}/udp"],
        ["firewall-cmd", "--permanent", "--zone=trusted", f"--add-interface={state['interface']}"],
    ]
    changed = False
    for cmd in cmds:
        proc = run(cmd, check=False)
        text = proc.stderr + proc.stdout
        if proc.returncode == 0:
            changed = True
        elif "ALREADY_ENABLED" not in text:
            warnings.append(f"firewalld: falha em {' '.join(cmd)}: {proc.stderr.strip() or proc.stdout.strip()}")
    if changed and run(["firewall-cmd", "--reload"], check=False).returncode != 0:
        warnings.append("firewalld: não foi possível recarregar regras.")
    return warnings

def perform_sync(payload):
    state = validate_state(payload)
    check_route_conflicts(state)
    if DRY_RUN:
        return {"ok": True, "dry_run": True, "message": "Estado validado; nenhuma alteração aplicada.", "peer_count": len(state["peers"]), "route_count": len(state["routes"]), "site_count": len(state["sites"]), "warnings": []}
    ensure_kernel_state(state)
    apply_wireguard(state)
    apply_routes(state)
    apply_nftables(state)
    warnings = configure_firewalld(state)
    return {"ok": True, "dry_run": False, "message": "WireGuard, rotas e isolamento sincronizados.", "peer_count": len(state["peers"]), "route_count": len(state["routes"]), "site_count": len(state["sites"]), "warnings": warnings}

def wireguard_status():
    interface = DEFAULT_INTERFACE
    if not interface_exists(interface):
        return {"ok": True, "dry_run": DRY_RUN, "interface": interface, "interface_up": False, "peers": {}}
    lines = [line.split("\t") for line in run(["wg", "show", interface, "dump"]).stdout.splitlines() if line.strip()]
    peers = {}
    for f in lines[1:]:
        if len(f) < 8: continue
        peers[f[0]] = {"endpoint": None if f[2] in ("(none)", "") else f[2], "allowed_ips": f[3], "latest_handshake": int(f[4] or 0), "rx_bytes": int(f[5] or 0), "tx_bytes": int(f[6] or 0), "persistent_keepalive": f[7]}
    return {"ok": True, "dry_run": DRY_RUN, "interface": interface, "interface_up": True, "peers": peers}

def health():
    status = wireguard_status()
    status["private_key_exists"] = Path(DEFAULT_PRIVATE_KEY).exists()
    status["nft_table"] = run(["nft", "list", "table", "inet", "vpnhub"], check=False).returncode == 0
    return status

def handle(req):
    action, payload = req.get("action"), req.get("payload") or {}
    if action == "health": return health()
    if action == "status": return wireguard_status()
    if action == "sync": return perform_sync(payload)
    return {"ok": False, "error": f"Ação não permitida: {action}"}

def main():
    path = Path(SOCKET_PATH); path.parent.mkdir(parents=True, exist_ok=True)
    try: path.unlink()
    except FileNotFoundError: pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH); os.chmod(SOCKET_PATH, 0o660); server.listen(32)
    while True:
        conn, _ = server.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk: break
                data += chunk
                if len(data) > 4 * 1024 * 1024: break
            try: resp = handle(json.loads(data.decode("utf-8")))
            except Exception as exc: resp = {"ok": False, "error": str(exc)}
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))

if __name__ == "__main__":
    main()
