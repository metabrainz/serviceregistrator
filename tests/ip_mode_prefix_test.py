import unittest
from serviceregistrator import ContainerMetadata, ServiceIP
from serviceregistrator.containerinfo import ContainerInfo
from serviceregistrator.registrator import Ports


class TestIpModePrefix(unittest.TestCase):
    """Tests for --ip-mode prefix: IP tag becomes service name prefix."""

    def test_prefix_mode_prepends_tag_to_name(self):
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.10.10.24", "virtual")],
            [],
            ip_mode="prefix",
        )
        svc = ci.services[0]
        assert svc.name == "virtual-pgbouncer-master"

    def test_prefix_mode_tag_still_in_consul_tags(self):
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.10.10.24", "virtual")],
            [],
            ip_mode="prefix",
        )
        svc = ci.services[0]
        assert "virtual" in svc.tags

    def test_prefix_mode_no_tag_no_prefix(self):
        """IP without a tag should not add any prefix."""
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.10.10.24")],
            [],
            ip_mode="prefix",
        )
        svc = ci.services[0]
        assert svc.name == "pgbouncer-master"

    def test_tag_mode_does_not_prefix_name(self):
        """Default tag mode should NOT prefix the service name."""
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.10.10.24", "virtual")],
            [],
            ip_mode="tag",
        )
        svc = ci.services[0]
        assert svc.name == "pgbouncer-master"
        assert "virtual" in svc.tags

    def test_prefix_mode_two_ips_same_address_one_tagged(self):
        """--ip 10.10.10.24@virtual --ip 10.10.10.24 produces two services."""
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.10.10.24", "virtual"), ServiceIP("10.10.10.24")],
            [],
            ip_mode="prefix",
        )
        services = ci.services
        names = sorted(s.name for s in services)
        assert names == ["pgbouncer-master", "virtual-pgbouncer-master"]

    def test_prefix_mode_two_different_ips_both_tagged(self):
        """Two IPs with different tags produce two prefixed services."""
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.2.2.24", "physical"), ServiceIP("10.10.10.24", "virtual")],
            [],
            ip_mode="prefix",
        )
        services = ci.services
        names = sorted(s.name for s in services)
        assert names == ["physical-pgbouncer-master", "virtual-pgbouncer-master"]

    def test_prefix_mode_service_id_still_has_tag(self):
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.10.10.24", "virtual")],
            [],
            ip_mode="prefix",
        )
        svc = ci.services[0]
        assert "@virtual" in svc.id

    def test_prefix_mode_untagged_ip_keeps_stable_id(self):
        """Untagged IP service ID has no hash/tag suffix — stays stable when adding a tagged IP."""
        ci = ContainerInfo(
            "cid",
            "cname",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "pgbouncer-master"}),
            {},
            "host",
            [ServiceIP("10.2.2.24"), ServiceIP("10.10.10.24", "virtual")],
            [],
            ip_mode="prefix",
        )
        services = {s.name: s for s in ci.services}
        # Untagged service keeps the plain ID (no @hash, no @tag)
        assert services["pgbouncer-master"].id == "host:cname:8080"
        # Tagged service gets @virtual
        assert services["virtual-pgbouncer-master"].id == "host:cname:8080@virtual"
