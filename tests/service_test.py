import unittest
from serviceregistrator.service import Service


class TestService(unittest.TestCase):
    def test_str(self):
        s = Service("cid123", "myid", "myname", "1.2.3.4", 80, tags=["t1"], attrs={"k": "v"})
        result = str(s)
        assert "myid" in result
        assert "myname" in result
        assert "1.2.3.4" in result

    def test_repr(self):
        s = Service("cid123", "myid", "myname", "1.2.3.4", 80, tags=["t1"], attrs={"k": "v"})
        result = repr(s)
        assert "cid123" in result
        assert "myid" in result

    def test_defaults_none_tags(self):
        # Documents the existing bug: `if not None` is always False
        s = Service("cid", "id", "name", "0.0.0.0", 80)
        # Due to the bug, tags/attrs will be None, not [] / {}
        assert s.tags is None
        assert s.attrs is None

    def test_explicit_tags_attrs(self):
        s = Service("cid", "id", "name", "0.0.0.0", 80, tags=["a"], attrs={"k": "v"})
        assert s.tags == ["a"]
        assert s.attrs == {"k": "v"}
