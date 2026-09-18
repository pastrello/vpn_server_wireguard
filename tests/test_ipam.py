from types import SimpleNamespace

from vpnhub.ipam import _site_subnets


def test_instance_pool_is_divided_into_site_24s():
    instance = SimpleNamespace(vpn_pool="10.250.0.0/16")
    subnets = _site_subnets(instance)

    assert str(next(subnets)) == "10.250.0.0/24"
    assert str(next(subnets)) == "10.250.1.0/24"


def test_independent_instances_can_define_independent_pools():
    first = SimpleNamespace(vpn_pool="10.250.0.0/16")
    second = SimpleNamespace(vpn_pool="10.251.0.0/16")

    assert str(next(_site_subnets(first))) == "10.250.0.0/24"
    assert str(next(_site_subnets(second))) == "10.251.0.0/24"
