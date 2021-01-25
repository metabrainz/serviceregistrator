import unittest
from serviceregistrator.registrator import ServiceRegistrator, Ports


class DummyContainer:
    attrs = {
        'NetworkSettings': {
            'Ports': {
                '180/udp': [{'HostIp': '127.0.0.1', 'HostPort': '18082'}],
                '80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '28082'},
                           {'HostIp': '0.0.0.0', 'HostPort': '8082'}]}
        },
        'HostConfig': {
            "NetworkMode": "default",
        },
        "Config": {
            "Hostname": "ifrit5",
            "ExposedPorts": {
                "180/udp": {},
                "80/tcp": {}
            },
        }
    }


class TestExtractPorts(unittest.TestCase):

    def setUp(self):
        self.container = DummyContainer()

    def test_extract_ports(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(set(ports), set([
            Ports(internal=180, external=18082, protocol='udp', ip='127.0.0.1'),
            Ports(internal=80, external=28082, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=80, external=8082, protocol='tcp', ip='0.0.0.0')]))

    def test_extract_ports_hostmode(self):
        self.container.attrs['HostConfig']['NetworkMode'] = 'host'
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(set(ports), set([
            Ports(internal=80, external=80, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=180, external=180, protocol='udp', ip='0.0.0.0'), ]))
