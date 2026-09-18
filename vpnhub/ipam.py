import ipaddress

from .models import AdminPeer, Peer, Site


def _site_subnets(instance):
    pool = ipaddress.ip_network(instance.vpn_pool, strict=False)

    if pool.version != 4 or pool.prefixlen > 24:
        raise RuntimeError(
            "VPN pool precisa ser IPv4 com prefixo /24 ou maior."
        )

    return pool.subnets(new_prefix=24)


def allocate_site_cidr(instance):
    used = {
        ipaddress.ip_network(site.vpn_cidr, strict=False)
        for site in Site.query.filter_by(
            vpn_instance_id=instance.id
        ).all()
    }

    subnets = _site_subnets(instance)

    # O primeiro /24 de cada Instance é reservado para servidor/Admin Peers.
    next(subnets, None)

    for candidate in subnets:
        if candidate not in used:
            return str(candidate)

    raise RuntimeError("Pool de Sites esgotado nesta VPN Instance.")


def allocate_peer_ip(site):
    network = ipaddress.ip_network(site.vpn_cidr, strict=False)
    used = {
        ipaddress.ip_interface(peer.assigned_ip).ip
        for peer in Peer.query.filter_by(site_id=site.id).all()
    }

    for index, host in enumerate(network.hosts(), start=1):
        if index < 10:
            continue
        if host not in used:
            return f"{host}/32"

    raise RuntimeError("Sem IPs disponíveis no Site.")


def allocate_admin_ip(instance):
    admin_network = next(_site_subnets(instance))
    used = {
        ipaddress.ip_interface(peer.assigned_ip).ip
        for peer in AdminPeer.query.filter_by(
            vpn_instance_id=instance.id
        ).all()
    }

    for index, host in enumerate(admin_network.hosts(), start=1):
        if index < 10:
            continue
        if host not in used:
            return f"{host}/32"

    raise RuntimeError(
        "Pool administrativo esgotado nesta VPN Instance."
    )
