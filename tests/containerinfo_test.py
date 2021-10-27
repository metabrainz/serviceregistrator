import unittest
from serviceregistrator import ContainerMetadata
from serviceregistrator.containerinfo import ContainerInfo
from serviceregistrator.registrator import Ports


class TestContainerInfo(unittest.TestCase):

    def setUp(self):
        ports = [Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')]
        metadata = ContainerMetadata({'name': 'dummyservice_name'})
        metadata_with_port = {80: ContainerMetadata({'name': 'dummyservice_80_name'})}
        container_id = 'deadbeef'
        service_name = 'dummyservice'
        hostname = 'my_host_name'
        ip = '127.6.6.6'
        tags = ['tag1', 'tag2']
        self.container_info = ContainerInfo(
            container_id,
            service_name,
            ports,
            metadata,
            metadata_with_port,
            hostname,
            ip,
            tags
        )

    def test_bool_both_metadata(self):
        self.assertTrue(self.container_info)

    def test_bool_only_metadata(self):
        self.container_info.metadata_with_port = {}
        self.assertTrue(self.container_info)

    def test_bool_only_metadata_with_ports(self):
        self.container_info.metadata = ContainerMetadata()
        self.assertTrue(self.container_info)

    def test_bool_no_metadata(self):
        self.container_info.metadata_with_port = {}
        self.container_info.metadata = ContainerMetadata()
        self.assertFalse(self.container_info)

    def test_get_attr(self):
        value = self.container_info.get_attr('name', 80)
        self.assertEqual(value, 'dummyservice_80_name')

    def test_get_attr_unknown_key(self):
        value = self.container_info.get_attr('XXX', 80)
        self.assertIsNone(value)

    def test_get_attr_no_port(self):
        value = self.container_info.get_attr('name', 81)
        self.assertEqual(value, 'dummyservice_name')

    def test_get_attr_port_metadata(self):
        self.container_info.metadata_with_port = {}
        value = self.container_info.get_attr('name', 80)
        self.assertEqual(value, 'dummyservice_name')

    def test_get_attr_no_port_no_metadata(self):
        self.container_info.metadata = ContainerMetadata()
        value = self.container_info.get_attr('name', 81)
        self.assertIsNone(value)

    def test_get_name(self):
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        value = self.container_info.get_name(port)
        self.assertEqual(value, 'dummyservice_80_name')

    def test_get_name_service_prefix(self):
        self.container_info.service_prefix = 'x'
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        value = self.container_info.get_name(port)
        self.assertEqual(value, (
            self.container_info.service_prefix
            + self.container_info.SERVICE_PREFIX_NAME_SEPARATOR
            + 'dummyservice_80_name'
            )
        )

    def test_get_name_none(self):
        self.container_info.metadata = ContainerMetadata()
        port = Ports(internal=81, external=8086, protocol='tcp', ip='0.0.0.0')
        value = self.container_info.get_name(port)
        self.assertIsNone(value)

    def test_names_count(self):
        counts = self.container_info.names_count()
        self.assertIn('dummyservice_80_name', counts)
        self.assertEqual(counts['dummyservice_80_name'], 1)

    def test_names_count_no_name(self):
        self.container_info.metadata = ContainerMetadata()
        self.container_info.ports = [Ports(internal=81, external=8086, protocol='tcp', ip='0.0.0.0')]
        counts = self.container_info.names_count()
        self.assertNotIn('dummyservice_80_name', counts)
        self.assertEqual(counts, {})

    def test_names_count_multiple_services(self):
        self.container_info.metadata = ContainerMetadata()
        self.container_info.metadata_with_port = {
            80: ContainerMetadata({'name': 'dummyservice_80_name'}),
            81: ContainerMetadata({'name': 'dummyservice_81_name'}),
        }

        self.container_info.ports = [
            Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=81, external=8087, protocol='tcp', ip='0.0.0.0'),
        ]
        counts = self.container_info.names_count()
        self.assertIn('dummyservice_80_name', counts)
        self.assertIn('dummyservice_81_name', counts)
        self.assertEqual(counts['dummyservice_80_name'], 1)
        self.assertEqual(counts['dummyservice_81_name'], 1)

    def test_names_count_multiple_services_same_name(self):
        self.container_info.metadata = ContainerMetadata({'name': 'dummyservice_name'})
        self.container_info.metadata_with_port = {}
        self.container_info.ports = [
            Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=81, external=8087, protocol='tcp', ip='0.0.0.0'),
        ]
        counts = self.container_info.names_count()
        self.assertIn('dummyservice_name', counts)
        self.assertEqual(counts['dummyservice_name'], 2)

    def test_build_service_name(self):
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        name = self.container_info.build_service_name(port)
        self.assertEqual(name, 'dummyservice_80_name')

    def test_build_service_name_no_matching_port(self):
        port = Ports(internal=81, external=8086, protocol='tcp', ip='0.0.0.0')
        name = self.container_info.build_service_name(port)
        self.assertIsNone(name)

    def test_build_service_name_multiple_services_same_name(self):
        self.container_info.metadata = ContainerMetadata({'name': 'dummyservice_name'})
        self.container_info.metadata_with_port = {}
        self.container_info.ports = [
            Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0'),
            Ports(internal=81, external=8087, protocol='tcp', ip='0.0.0.0'),
        ]
        name = self.container_info.build_service_name(self.container_info.ports[0])
        self.assertEqual(name, 'dummyservice_name-8086')

        name = self.container_info.build_service_name(self.container_info.ports[1])
        self.assertEqual(name, 'dummyservice_name-8087')

    def test_build_service_name_multiple_services_same_name_udp(self):
        self.container_info.metadata = ContainerMetadata({'name': 'dummyservice_name'})
        self.container_info.metadata_with_port = {}
        self.container_info.ports = [
            Ports(internal=80, external=8086, protocol='udp', ip='0.0.0.0'),
            Ports(internal=81, external=8087, protocol='tcp', ip='0.0.0.0'),
        ]
        name = self.container_info.build_service_name(self.container_info.ports[0])
        self.assertEqual(name, 'dummyservice_name-8086-udp')

    def test_services_tags(self):
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        tags = self.container_info.build_service_tags(port)
        self.assertEqual(set(tags), set(['tag2', 'tag1']))

    def test_services_tags_metadata(self):
        self.container_info.metadata = ContainerMetadata({'tags': 'tag3,tag4'})
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        tags = self.container_info.build_service_tags(port)
        self.assertEqual(set(tags), set(['tag4', 'tag3', 'tag2', 'tag1']))

    def test_services_tags_metadata_notags(self):
        self.container_info.tags = []
        self.container_info.metadata = ContainerMetadata({'tags': 'tag3,tag4'})
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        tags = self.container_info.build_service_tags(port)
        self.assertEqual(set(tags), set(['tag4', 'tag3']))

    def test_services_tags_udp(self):
        port = Ports(internal=80, external=8086, protocol='udp', ip='0.0.0.0')
        tags = self.container_info.build_service_tags(port)
        self.assertEqual(set(tags), set(['tag2', 'tag1', 'udp']))

    def test_build_service_attrs(self):
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        attrs = self.container_info.build_service_attrs(port)
        self.assertEqual(attrs, {})

    def test_build_service_attrs_metadata(self):
        self.container_info.metadata_with_port = {80: ContainerMetadata({'attrs': {'k': 'v'}})}
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        attrs = self.container_info.build_service_attrs(port)
        self.assertEqual(attrs, {'k': 'v'})

    def test_build_service_id(self):
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        service_id = self.container_info.build_service_id(port)
        self.assertEqual(service_id, self.container_info.SERVICE_ID_SEPARATOR.join(
            ('my_host_name', 'dummyservice', '8086')))

    def test_build_service_id_prefix(self):
        self.container_info.service_prefix = 'x'
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        service_id = self.container_info.build_service_id(port)
        self.assertEqual(service_id, self.container_info.SERVICE_ID_SEPARATOR.join(
            (self.container_info.service_prefix, 'my_host_name', 'dummyservice', '8086')))

    def test_build_service_id_udp(self):
        port = Ports(internal=80, external=8086, protocol='udp', ip='0.0.0.0')
        service_id = self.container_info.build_service_id(port)
        self.assertEqual(service_id, self.container_info.SERVICE_ID_SEPARATOR.join(
            ('my_host_name', 'dummyservice', '8086', 'udp')))

    def test_build_service_id_udp_prefix(self):
        self.container_info.service_prefix = 'x'
        port = Ports(internal=80, external=8086, protocol='udp', ip='0.0.0.0')
        service_id = self.container_info.build_service_id(port)
        self.assertEqual(service_id, self.container_info.SERVICE_ID_SEPARATOR.join(
            (self.container_info.service_prefix, 'my_host_name', 'dummyservice', '8086', 'udp')))

    def test_build_service_ip(self):
        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        ip = self.container_info.build_service_ip(port)
        self.assertEqual(ip, '127.6.6.6')

    def test_build_service_ip_metadata(self):
        self.container_info.metadata = ContainerMetadata({'ip': '1.2.3.4'})

        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        ip = self.container_info.build_service_ip(port)
        self.assertEqual(ip, '1.2.3.4')

    def test_build_service_ip_metadata_port(self):
        self.container_info.metadata_with_port = {80: ContainerMetadata({'ip': '4.3.2.1'})}

        port = Ports(internal=80, external=8086, protocol='tcp', ip='0.0.0.0')
        ip = self.container_info.build_service_ip(port)
        self.assertEqual(ip, '4.3.2.1')

    def test_services(self):
        services = self.container_info.services
        id1 = self.container_info.SERVICE_ID_SEPARATOR.join(
            ('my_host_name', 'dummyservice', '8086'))
        self.assertEqual(services[0].id, id1)
        services = self.container_info.services
        self.assertIsNotNone(self.container_info._services)

    def test_services_multiple(self):
        self.container_info.metadata = ContainerMetadata({'name': 'dummyservice_name'})
        self.container_info.metadata_with_port = {}
        self.container_info.ports = [
            Ports(internal=80, external=8086, protocol='udp', ip='0.0.0.0'),
            Ports(internal=81, external=8087, protocol='tcp', ip='0.0.0.0'),
        ]
        identifiers = self.container_info.service_identifiers()
        id1 = self.container_info.SERVICE_ID_SEPARATOR.join(
            ('my_host_name', 'dummyservice', '8086', 'udp'))
        id2 = self.container_info.SERVICE_ID_SEPARATOR.join(
            ('my_host_name', 'dummyservice', '8087'))
        self.assertIn(id1, identifiers)
        self.assertIn(id2, identifiers)

    def test_services_no_name(self):
        self.container_info.metadata = ContainerMetadata({'name': ''})
        self.container_info.metadata_with_port = {}
        services = self.container_info.services
        self.assertEqual(services, [])
