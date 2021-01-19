import unittest
from serviceregistrator.main import ServiceRegistrator, Ports


class DummyContainer:
    attrs = {'NetworkSettings': {
            'Ports': {
                '180/udp': [{'HostIp': '0.0.0.0', 'HostPort': '18082'}],
                '80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '28082'},
                           {'HostIp': '0.0.0.0', 'HostPort': '8082'}]}
        }
        }


class TestExtractPorts(unittest.TestCase):

    def setUp(self):
        self.container = DummyContainer()

    def test_extract_ports(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(ports, [
            Ports(internal='180', external=18082, protocol='udp'),
            Ports(internal='80', external=28082, protocol='tcp'),
            Ports(internal='80', external=8082, protocol='tcp')])
