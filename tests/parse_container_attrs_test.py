import unittest
from serviceregistrator import ContainerMetadata
from serviceregistrator.registrator import ServiceRegistrator


class DummyContainer:
    attrs = {'Config': {
        'Env': [
            "SERVICE_CHECK_TIMEOUT=15s",
            "SERVICE_80_CHECK_TCP=true",
            "SERVICE_80_CHECK_TIMEOUT=10s",
            "SERVICE_80_NAME=dummyservice",
            "SERVICE_NAME=dummyservicenoportfromenv",
            "SERVICE_TAGS=noporttag",
            'OTHER=zzz',
        ]
    }
    }
    labels = {
        "SERVICE_180_CHECK_TCP": "false",
        "SERVICE_180_NAME": "dummyservice180",
        "SERVICE_CHECK_INTERVAL": "25s",
        "SERVICE_80_TAGS": "prod,dummytag",
        "SERVICE_NAME": "dummyservicenoportfromlabel",
        'OTHER': 'zzz',
    }


class TestParsers(unittest.TestCase):

    def setUp(self):
        self.container = DummyContainer()

    def test_parse_env(self):
        kv = ServiceRegistrator.parse_env(self.container.attrs['Config']['Env'])
        self.assertEqual(kv,
                         {'80_CHECK_TCP': 'true',
                          '80_CHECK_TIMEOUT': '10s',
                          '80_NAME': 'dummyservice',
                          'CHECK_TIMEOUT': '15s',
                          'NAME': 'dummyservicenoportfromenv',
                          'TAGS': 'noporttag'})

    def test_parse_labels(self):
        kv = ServiceRegistrator.parse_labels(self.container.labels)
        self.assertEqual(kv,
                         {'180_CHECK_TCP': 'false',
                          '180_NAME': 'dummyservice180',
                          '80_TAGS': 'prod,dummytag',
                          'CHECK_INTERVAL': '25s',
                          'NAME': 'dummyservicenoportfromlabel'})

    def test_parse_service_meta(self):
        metadata, metadata_with_port = ServiceRegistrator.parse_service_meta(self.container)
        self.assertIsInstance(metadata, ContainerMetadata)
        self.assertIsInstance(metadata_with_port, dict)
        self.assertEqual(metadata, ContainerMetadata(
            {'attrs': {'check_interval': '25s', 'check_timeout': '15s'},
             'name': 'dummyservicenoportfromenv',
             'tags': ['noporttag']
             }))

        self.assertIn(80, metadata_with_port)
        self.assertIn(180, metadata_with_port)

        self.assertEqual(
            metadata_with_port[80]['attrs'],
            {'check_interval': '25s', 'check_timeout': '10s', 'check_tcp': 'true'}
        )
        self.assertEqual(
            metadata_with_port[80]['name'],
            'dummyservice'
        )
        self.assertEqual(
            set(metadata_with_port[80]['tags']),
            set(['dummytag', 'prod', 'noporttag'])
        )

        self.assertEqual(
            metadata_with_port[180]['attrs'],
            {'check_interval': '25s', 'check_timeout': '15s', 'check_tcp': 'false'}
        )
        self.assertEqual(
            metadata_with_port[180]['name'],
            'dummyservice180'
        )
        self.assertEqual(
            metadata_with_port[180]['tags'],
            ['noporttag']
        )
