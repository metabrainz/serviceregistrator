import unittest
from unittest.mock import Mock, patch, MagicMock
from serviceregistrator import ContainerMetadata, Context


class TestContainerMetadataExtra(unittest.TestCase):

    def test_repr(self):
        m = ContainerMetadata({'name': 'x'})
        r = repr(m)
        assert 'ContainerMetadata' in r
        assert 'name' in r

    def test_set_id(self):
        m = ContainerMetadata()
        m['id'] = 'myid'
        assert m['id'] == 'myid'

    def test_set_ip(self):
        m = ContainerMetadata()
        m['ip'] = '1.2.3.4'
        assert m['ip'] == '1.2.3.4'

    def test_tags_none(self):
        m = ContainerMetadata()
        m['tags'] = None
        assert m['tags'] == []

    def test_tags_merge_dedup(self):
        m = ContainerMetadata()
        m['tags'] = 'a,b'
        m['tags'] = 'b,c'
        assert set(m['tags']) == {'a', 'b', 'c'}

    def test_attrs_merge(self):
        m = ContainerMetadata()
        m['foo'] = 'bar'
        m['baz'] = 'qux'
        assert m['attrs'] == {'foo': 'bar', 'baz': 'qux'}

    def test_attrs_from_dict_merge(self):
        m = ContainerMetadata({'attrs': {'k1': 'v1'}})
        m['k2'] = 'v2'
        assert m['attrs'] == {'k1': 'v1', 'k2': 'v2'}


class TestContext(unittest.TestCase):

    @patch('serviceregistrator.signal.signal')
    @patch('serviceregistrator.signal.setitimer')
    def test_init_with_resync(self, mock_setitimer, mock_signal):
        options = {
            'resync': 30,
            'logfile': None,
            'loglevel': 'INFO',
        }
        ctx = Context(options)
        assert ctx.options == options
        assert ctx.kill_now is False
        mock_setitimer.assert_called_once()

    @patch('serviceregistrator.signal.signal')
    def test_init_no_resync(self, mock_signal):
        options = {
            'resync': 0,
            'logfile': None,
            'loglevel': 'INFO',
        }
        ctx = Context(options)
        assert ctx.kill_now is False

    @patch('serviceregistrator.signal.signal')
    def test_exit_gracefully(self, mock_signal):
        options = {'resync': 0, 'logfile': None, 'loglevel': 'INFO'}
        ctx = Context(options)
        callback = Mock()
        ctx.register_on_exit('test', callback)
        ctx.exit_gracefully(2, None)  # SIGINT=2
        assert ctx.kill_now is True
        callback.assert_called_once()

    @patch('serviceregistrator.signal.signal')
    def test_ignore_signal(self, mock_signal):
        options = {'resync': 0, 'logfile': None, 'loglevel': 'INFO'}
        ctx = Context(options)
        # Should not raise
        ctx.ignore_signal(10, None)  # SIGUSR1=10

    @patch('serviceregistrator.signal.signal')
    def test_sync_with_containers_signal(self, mock_signal):
        options = {'resync': 0, 'logfile': None, 'loglevel': 'INFO'}
        ctx = Context(options)
        mock_sr = Mock()
        ctx.serviceregistrator = mock_sr
        ctx.sync_with_containers(1, None)  # SIGHUP=1
        mock_sr.sync_with_containers.assert_called_once()

    @patch('serviceregistrator.signal.signal')
    def test_sync_with_containers_no_registrator(self, mock_signal):
        options = {'resync': 0, 'logfile': None, 'loglevel': 'INFO'}
        ctx = Context(options)
        # Should not raise when serviceregistrator is None
        ctx.sync_with_containers(1, None)

    @patch('serviceregistrator.signal.signal')
    def test_configure_logging_with_logfile(self, mock_signal):
        options = {'resync': 0, 'logfile': '/tmp/test_sr.log', 'loglevel': 'DEBUG'}
        ctx = Context(options)
        # Just verify it doesn't crash

    @patch('serviceregistrator.signal.signal')
    def test_configure_logging_invalid_level(self, mock_signal):
        options = {'resync': 0, 'logfile': None, 'loglevel': 'INVALID'}
        # Should not raise, just log an error
        ctx = Context(options)

    @patch('serviceregistrator.signal.signal')
    def test_configure_logging_bad_logfile(self, mock_signal):
        options = {'resync': 0, 'logfile': '/nonexistent/dir/file.log', 'loglevel': 'INFO'}
        # Should not raise due to bare except
        ctx = Context(options)

    @patch('serviceregistrator.signal.signal')
    def test_signal_name_caching(self, mock_signal):
        options = {'resync': 0, 'logfile': None, 'loglevel': 'INFO'}
        ctx = Context(options)
        assert ctx._sig2name is None
        ctx._log_signal(2)
        assert ctx._sig2name is not None
        # Second call uses cache
        ctx._log_signal(2)
