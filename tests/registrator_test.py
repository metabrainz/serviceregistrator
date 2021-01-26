import unittest
from unittest.mock import Mock
from serviceregistrator.registrator import ServiceRegistrator


class TestIsOurIdentifier(unittest.TestCase):
    def setUp(self):
        def dummyfunc(x):
            pass

        ServiceRegistrator._init_consul = dummyfunc
        ServiceRegistrator._init_docker = dummyfunc
        context = Mock()
        self.registrator = ServiceRegistrator(context)
        self.registrator.hostname = 'my_hostname'

    def test_too_short(self):
        yes, comment = self.registrator.is_our_identifier('x')
        self.assertFalse(yes)
        self.assertEqual(comment, 'length < 3')

    def test_too_short_different_prefix(self):
        yes, comment = self.registrator.is_our_identifier('x', prefix='abc')
        self.assertFalse(yes)
        self.assertEqual(comment, 'different prefix')

    def test_too_short_same_prefix(self):
        yes, comment = self.registrator.is_our_identifier('abc:x', prefix='abc')
        self.assertFalse(yes)
        self.assertEqual(comment, 'length < 3')

    def test_too_short_2elems(self):
        yes, comment = self.registrator.is_our_identifier('x:y')
        self.assertFalse(yes)
        self.assertEqual(comment, 'length < 3')

    def test_3elems_different_hostname(self):
        yes, comment = self.registrator.is_our_identifier('x:y:z')
        self.assertFalse(yes)
        self.assertEqual(comment, 'different hostname')

    def test_3elems_same_hostname(self):
        yes, comment = self.registrator.is_our_identifier(self.registrator.hostname + ':y:z')
        self.assertTrue(yes)
        self.assertIsNone(comment)

    def test_3elems_same_hostname_different_prefix(self):
        yes, comment = self.registrator.is_our_identifier(self.registrator.hostname + ':y:z', prefix='abc')
        self.assertFalse(yes)
        self.assertEqual(comment, 'different prefix')

    def test_3elems_same_hostname_same_prefix(self):
        yes, comment = self.registrator.is_our_identifier('abc:' + self.registrator.hostname + ':y:z', prefix='abc')
        self.assertTrue(yes)
        self.assertIsNone(comment)

    def test_4elems_same_hostname_same_prefix_no_udp(self):
        yes, comment = self.registrator.is_our_identifier('abc:' + self.registrator.hostname + ':y:z:hhh', prefix='abc')
        self.assertFalse(yes)
        self.assertEqual(comment, 'no udp')

    def test_4elems_same_hostname_same_prefix_udp(self):
        yes, comment = self.registrator.is_our_identifier('abc:' + self.registrator.hostname + ':y:z:udp', prefix='abc')
        self.assertTrue(yes)
        self.assertIsNone(comment)
