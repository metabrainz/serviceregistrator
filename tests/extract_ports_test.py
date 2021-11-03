import unittest
from serviceregistrator.registrator import ServiceRegistrator, Ports


class TestExtractPortsExposedNotUsed(unittest.TestCase):
    def setUp(self):
        class DummyContainer:
            attrs = {
                'NetworkSettings': {
                    'Ports': {
                        '9200/tcp': [
                            {'HostIp': '0.0.0.0', 'HostPort': '65423'},
                            {'HostIp': '::', 'HostPort': '65423'}
                        ],
                        '9300/tcp': None   # this happens when port is exposed in Dockerfile, but not published
                    }
                },
                'HostConfig': {
                    "NetworkMode": "default",
                }
            }
        self.container = DummyContainer()

    def test_extract_ports(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(set(ports), set([
            Ports(internal=9200, external=65423, protocol='tcp', ip='0.0.0.0')
        ]))


class TestExtractPortsDefault(unittest.TestCase):
    def setUp(self):
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
                    "Hostname": "my_hostname",
                    "ExposedPorts": {
                        "180/udp": {},
                        "80/tcp": {}
                    },
                }
            }

        self.container = DummyContainer()

    def test_extract_ports(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(set(ports), set([
            Ports(internal=180, external=18082, protocol='udp', ip='127.0.0.1'),
            Ports(internal=80, external=28082, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=80, external=8082, protocol='tcp', ip='0.0.0.0')]))

    def test_extract_ports_no_port_no_bindings(self):
        self.container.attrs['HostConfig']['PortBindings'] = {}
        self.container.attrs['NetworkSettings']['Ports'] = {}
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(ports, [])

    def test_extract_ports_no_port_but_bindings(self):
        self.container.attrs['HostConfig']['PortBindings'] = self.container.attrs['NetworkSettings']['Ports'].copy()
        self.container.attrs['NetworkSettings']['Ports'] = {}
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(set(ports), set([
            Ports(internal=180, external=18082, protocol='udp', ip='127.0.0.1'),
            Ports(internal=80, external=28082, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=80, external=8082, protocol='tcp', ip='0.0.0.0')]))


class TestExtractPortsBridge(TestExtractPortsDefault):

    def setUp(self):
        super().setUp()
        self.container.attrs['HostConfig']['NetworkMode'] = 'bridge'


class TestExtractPortsOther(TestExtractPortsDefault):

    def setUp(self):
        super().setUp()
        self.container.attrs['HostConfig']['NetworkMode'] = 'other'

    def test_extract_ports(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(ports, [])

    def test_extract_ports_no_port_no_bindings(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(ports, [])

    def test_extract_ports_no_port_but_bindings(self):
        self.container.attrs['HostConfig']['PortBindings'] = self.container.attrs['NetworkSettings']['Ports'].copy()
        self.container.attrs['NetworkSettings']['Ports'] = {}
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(ports, [])


class TestExtractPortsHost(unittest.TestCase):

    def setUp(self):
        class DummyContainer:
            attrs = {
                'NetworkSettings': {
                    'Networks': {
                        'host': {
                            'IPAddress': '',
                        }
                    }
                },
                'HostConfig': {
                    "NetworkMode": "host",
                },
                "Config": {
                    "Hostname": "my_hostname",
                    "ExposedPorts": {
                        "180/udp": {},
                        "80/tcp": {}
                    },
                }
            }

        self.container = DummyContainer()

    def test_extract_ports(self):
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(set(ports), set([
            Ports(internal=80, external=80, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=180, external=180, protocol='udp', ip='0.0.0.0'), ]))

    def test_extract_ports_no_port(self):
        self.container.attrs['Config']['ExposedPorts'] = {}
        ports = ServiceRegistrator.extract_ports(self.container)
        self.assertEqual(ports, [])
