import unittest
from serviceregistrator import ContainerMetadata


class TestContainerMetadata(unittest.TestCase):

    def setUp(self):
        self.metadata = ContainerMetadata()

    def test_class(self):
        self.assertIsInstance(self.metadata, ContainerMetadata)

    def test_key_name(self):
        """Basic testing, key=name"""
        key = 'name'
        self.metadata[key] = 'xxx'
        self.assertEqual(self.metadata[key], 'xxx')
        self.metadata[key] = 'yyy'
        self.assertEqual(self.metadata[key], 'yyy')
        del self.metadata[key]
        with self.assertRaises(KeyError):
            del self.metadata[key]

    def test_key_akey(self):
        """Basic testing, key=akey"""
        key = 'akey'
        self.metadata[key] = 'xxx'

        def get_key():
            return self.metadata[key]
        self.assertRaises(KeyError, get_key)
        # this one should go in attrs
        self.assertEqual(self.metadata['attrs'][key], 'xxx')
        self.metadata[key] = 'yyy'
        self.assertEqual(self.metadata['attrs'][key], 'yyy')

    def test_key_tags(self):
        """Basic testing, key=tags"""
        key = 'tags'
        self.metadata[key] = 'xxx'
        self.assertEqual(self.metadata[key], ['xxx'])
        self.metadata[key] = 'yyy'
        self.assertEqual(set(self.metadata[key]), set(['xxx', 'yyy']))
        self.metadata[key] = ['zzz', 'aaa']
        self.assertEqual(set(self.metadata[key]), set(['xxx', 'yyy', 'zzz', 'aaa']))
        del self.metadata[key]
        with self.assertRaises(KeyError):
            del self.metadata[key]

    def test_from_dict(self):
        a = ContainerMetadata({'tags': ['a', 'b', ''], 'attrs': {'k': 'v'}, 'name': 'x'})
        a['tags'] = 'c'
        a['k2'] = 'v2'
        a['name'] = 'y'
        self.assertEqual(set(a['tags']), set(['a', 'b', 'c']))
        self.assertEqual(a['attrs'], {'k': 'v', 'k2': 'v2'})
        self.assertEqual(a['name'], 'y')
