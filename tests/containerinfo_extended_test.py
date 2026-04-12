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
            "127.0.0.1",
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
            "127.0.0.1",
            [],
        )
        port = Ports(internal=80, external=8080, protocol="tcp", ip="10.0.0.5")
        ip = ci.build_service_ip(port)
        assert ip == "10.0.0.5"

    def test_port_ip_ipv6_wildcard(self):
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="::")],
            ContainerMetadata({"name": "svc"}),
            {},
            "host",
            "127.0.0.1",
            [],
        )
        port = Ports(internal=80, external=8080, protocol="tcp", ip="::")
        ip = ci.build_service_ip(port)
        assert ip == "127.0.0.1"

    def test_port_ip_empty(self):
        ci = ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="")],
            ContainerMetadata({"name": "svc"}),
            {},
            "host",
            "127.0.0.1",
            [],
        )
        port = Ports(internal=80, external=8080, protocol="tcp", ip="")
        ip = ci.build_service_ip(port)
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
            "127.0.0.1",
            [],
        )
        services = ci.services
        assert len(services) == 2
        names = [s.name for s in services]
        assert "svc-8080" in names
        assert "svc-8081" in names

    def test_duplicate_service_name_skipped(self):
        """Force build_service_name to return same name for two ports — second is skipped."""

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
            "127.0.0.1",
            [],
        )
        # Monkey-patch build_service_name to always return the same name
        ci.build_service_name = lambda port: "svc"
        services = ci.services
        assert len(services) == 1


class TestBuildServiceIpValidation(unittest.TestCase):
    def _make_ci(self, service_ip_override):
        return ContainerInfo(
            "cid",
            "name",
            [Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0")],
            ContainerMetadata({"name": "svc", "ip": service_ip_override}),
            {},
            "host",
            "127.0.0.1",
            [],
        )

    def test_valid_ipv4(self):
        ci = self._make_ci("10.0.0.1")
        ip = ci.build_service_ip(Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0"))
        assert ip == "10.0.0.1"

    def test_valid_ipv6(self):
        ci = self._make_ci("::1")
        ip = ci.build_service_ip(Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0"))
        assert ip == "::1"

    def test_invalid_ip_shell_injection(self):
        ci = self._make_ci("$(whoami)")
        ip = ci.build_service_ip(Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0"))
        assert ip == "127.0.0.1"  # falls back to default

    def test_invalid_ip_arbitrary_string(self):
        ci = self._make_ci("not-an-ip; rm -rf /")
        ip = ci.build_service_ip(Ports(internal=80, external=8080, protocol="tcp", ip="0.0.0.0"))
        assert ip == "127.0.0.1"
