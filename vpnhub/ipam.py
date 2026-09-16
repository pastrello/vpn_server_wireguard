import ipaddress
from flask import current_app
from .models import Site, Peer, AdminPeer

def allocate_site_cidr():
    pool=ipaddress.ip_network(current_app.config['VPN_ADDRESS_POOL'])
    used={ipaddress.ip_network(s.vpn_cidr) for s in Site.query.all()}
    for candidate in list(pool.subnets(new_prefix=24))[1:]:
        if candidate not in used:
            return str(candidate)
    raise RuntimeError('Pool de sites esgotado.')

def allocate_peer_ip(site):
    net=ipaddress.ip_network(site.vpn_cidr)
    used={ipaddress.ip_interface(p.assigned_ip).ip for p in Peer.query.filter_by(site_id=site.id).all()}
    for host in list(net.hosts())[9:]:
        if host not in used:
            return f'{host}/32'
    raise RuntimeError('Sem IPs disponíveis no site.')

def allocate_admin_ip():
    pool=ipaddress.ip_network(current_app.config['VPN_ADDRESS_POOL'])
    admin_net=next(pool.subnets(new_prefix=24))
    used={ipaddress.ip_interface(p.assigned_ip).ip for p in AdminPeer.query.all()}
    for host in list(admin_net.hosts())[9:]:
        if host not in used:
            return f'{host}/32'
    raise RuntimeError('Pool administrativo esgotado.')
