import unittest
from serviceregistrator import ContainerMetadata
from serviceregistrator.containerinfo import ContainerInfo
from serviceregistrator.registrator import Ports


class TestContainerInfoStringRepresentations(unittest.TestCase):
    def setUp(self):
        self.ci = ContainerInfo(
            "deadbeef1234",
            "mycontainer",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "svc"}),
            {},
            "myhost",
            [("127.0.0.1", None)],
            [],
        )

    def test_str(self):
        s = str(self.ci)
        assert "ContainerInfo" in s
        assert "mycontainer" in s
        assert "deadbeef12" in s

    def test_repr(self):
        r = repr(self.ci)
        assert "ContainerInfo" in r
        assert "deadbeef1234" in r
        assert "mycontainer" in r


class TestBuildServiceIpPortSpecific(unittest.TestCase):
    def test_port_ip_not_wildcard(self):
        """When port.ip is a real address (not 0.0.0.0/::/''), use it."""
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="10.0.0.5")],
            ContainerMetadata({"name": "svc"}),
            {},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "10.0.0.5"

    def test_port_ip_ipv6_wildcard(self):
        """Wildcard :: is expanded to the default --ip."""
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="::")],
            ContainerMetadata({"name": "svc"}),
            {},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "127.0.0.1"

    def test_port_ip_empty(self):
        """Empty IP is expanded to the default --ip."""
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="")],
            ContainerMetadata({"name": "svc"}),
            {},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "127.0.0.1"


class TestServicesDuplicateName(unittest.TestCase):
    def test_multi_port_same_internal(self):
        """Two ports resolving to the same base name get suffixed."""
        ci = ContainerInfo(
            "cid",
            "name",
            [
                Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0"),
                Ports(internal=80, external=8081, protocol="tcp", ip="0.0.0.0"),
            ],
            ContainerMetadata(),
            {80: ContainerMetadata({"name": "svc"})},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        services = ci.services
        assert len(services) == 2
        names = [s.name for s in services]
        assert "svc-8080" in names
        assert "svc-8081" in names

    def test_duplicate_service_name_different_ids_allowed(self):
        """Same service name on different ports with different IDs — both registered."""

        ci = ContainerInfo(
            "cid",
            "name",
            [
                Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0"),
                Ports(internal=81, external=8081, protocol="tcp", ip="0.0.0.0"),
            ],
            ContainerMetadata({"name": "svc"}),
            {},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        # Monkey-patch build_service_name to always return the same name
        ci.build_service_name = lambda port: "svc"
        services = ci.services
        assert len(services) == 2
        # Both have the same name but different IDs
        assert services[0].name == services[1].name == "svc"
        assert services[0].id != services[1].id


class TestBuildServiceIpValidation(unittest.TestCase):
    def _make_ci(self, service_ip_override):
        return ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "svc", "ip": service_ip_override}),
            {},
            "host",
            [("127.0.0.1", None)],
            [],
        )

    def test_valid_ipv4(self):
        ci = self._make_ci("10.0.0.1")
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "10.0.0.1"

    def test_valid_ipv6(self):
        ci = self._make_ci("::1")
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "::1"

    def test_invalid_ip_shell_injection(self):
        ci = self._make_ci("$(whoami)")
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "127.0.0.1"  # falls back to default

    def test_invalid_ip_arbitrary_string(self):
        ci = self._make_ci("not-an-ip; rm -rf /")
        ip = ci.build_service_ip(ci.ports[0])
        assert ip == "127.0.0.1"


class TestBuildServiceAlias(unittest.TestCase):
    def test_alias_creates_extra_service(self):
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata(),
            {80: ContainerMetadata({"name": "real-svc", "alias": "alias-svc"})},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        services = ci.services
        assert len(services) == 2
        names = {s.name for s in services}
        assert "real-svc" in names
        assert "alias-svc" in names

        alias = [s for s in services if s.name == "alias-svc"][0]
        assert alias.alias_of == "real-svc"
        assert alias.port == 8080
        assert alias.ip == "127.0.0.1"
        assert alias.id.endswith(":alias")

    def test_no_alias_no_extra_service(self):
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata(),
            {80: ContainerMetadata({"name": "real-svc"})},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        services = ci.services
        assert len(services) == 1
        assert services[0].alias_of is None

    def test_alias_inherits_tags(self):
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata(),
            {80: ContainerMetadata({"name": "real-svc", "alias": "alias-svc", "tags": "prod,db"})},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        alias = [s for s in ci.services if s.name == "alias-svc"][0]
        assert "prod" in alias.tags
        assert "db" in alias.tags

    def test_alias_name_collision_with_service_name(self):
        """Alias name same as service name — both registered (different IDs)."""
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata(),
            {80: ContainerMetadata({"name": "real-svc", "alias": "real-svc"})},
            "host",
            [("127.0.0.1", None)],
            [],
        )
        services = ci.services
        assert len(services) == 2
        real = [s for s in services if s.alias_of is None][0]
        alias = [s for s in services if s.alias_of is not None][0]
        assert real.name == "real-svc"
        assert alias.name == "real-svc"
        assert alias.id.endswith(":alias")
