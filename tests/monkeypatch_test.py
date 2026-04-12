"""Tests for the monkey-patched Container.health property and __repr__."""
import unittest


class TestContainerHealthMonkeyPatch(unittest.TestCase):

    def test_health_with_status(self):
        # Import triggers the monkey patch
        from serviceregistrator.registrator import health

        class FakeContainer:
            attrs = {'State': {'Health': {'Status': 'healthy'}}}

        c = FakeContainer()
        assert health.fget(c) == 'healthy'

    def test_health_without_health_key(self):
        from serviceregistrator.registrator import health

        class FakeContainer:
            attrs = {'State': {}}

        c = FakeContainer()
        assert health.fget(c) == 'none'

    def test_health_none_value(self):
        from serviceregistrator.registrator import health

        class FakeContainer:
            attrs = {'State': {'Health': None}}

        c = FakeContainer()
        assert health.fget(c) == 'none'
