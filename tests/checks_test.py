import pytest
import unittest
from serviceregistrator.service import Service
from serviceregistrator.servicecheck import ServiceCheck


class TestServiceCheckFunctions(unittest.TestCase):
    def setUp(self):
        ServiceCheck.defaults = {
            'key': 'defval'
        }
        self.params = {
            'key': 'val'
        }

    def test_value(self):
        value = ServiceCheck._value(self.params, 'key')
        self.assertEqual(value, 'val')

    def test_value_default(self):
        del self.params['key']
        value = ServiceCheck._value(self.params, 'key')
        self.assertEqual(value, 'defval')

    def test_no_default(self):
        value = ServiceCheck._value(self.params, 'unknownkey')
        self.assertIsNone(value)

    def test_bool_value_true(self):
        self.params['key'] = 'true'
        value = ServiceCheck._bool_value(self.params, 'key')
        self.assertTrue(value)

    def test_bool_value_false(self):
        self.params['key'] = 'untrue'
        value = ServiceCheck._bool_value(self.params, 'key')
        self.assertFalse(value)

    def test_json_value_ok(self):
        self.params['key'] = '{"k": "v"}'
        value = ServiceCheck._json_value(self.params, 'key')
        self.assertIn('k', value)
        self.assertEqual(value['k'], 'v')

    def test_json_value_not_ok(self):
        self.params['key'] = '{"k": "v",}'
        value = ServiceCheck._json_value(self.params, 'key')
        self.assertIsNone(value)

    def test_json_value_empty(self):
        self.params['key'] = ''
        value = ServiceCheck._json_value(self.params, 'key')
        self.assertIsNone(value)


class DummyService(Service):

    def __init__(self):
        super().__init__('deadbeef', 'serviceid', 'servicename', '6.6.6.6',
                         666, tags=['tag1', 'tag2'],
                         attrs={'key1': 'value1', 'key2': 'value2'})


class TestServiceCheckHttp(unittest.TestCase):

    def setUp(self):
        ServiceCheck.consul_version = (1, 7, 0)
        self.dummyservice = DummyService()
        self.params_http = {
            'http': '/path',
            'interval': '17s',
            'timeout': '3s',
            'header': '{"x-foo": ["bar", "baz"]}',
            'http_method': 'head',
            'body': 'bodycontent',
            'deregister': '666s',
            'initial_status': 'passing',
        }

        self.params_https = {
            'https': '/path',
            'interval': '17s',
            'timeout': '3s',
            'header': '{"x-foo": ["bar", "baz"]}',
            'https_method': 'head',
            'body': 'bodycontent',
        }

    def test_check_http(self):
        params = self.params_http
        check = ServiceCheck.http(self.dummyservice, params)
        self.assertEqual(check['http'], 'http://6.6.6.6:666/path')
        self.assertEqual(check['interval'], '17s')
        self.assertEqual(check['timeout'], '3s')
        self.assertEqual(check['header'], {'x-foo': ['bar', 'baz']})
        self.assertEqual(check['Method'], 'HEAD')
        self.assertEqual(check['Body'], params['body'])
        self.assertEqual(check['DeregisterCriticalServiceAfter'], '666s')
        self.assertEqual(check['Status'], 'passing')
        self.assertEqual(len(check), 8)

    def test_check_http_no_path(self):
        params = self.params_http
        params['http'] = ''
        check = ServiceCheck.http(self.dummyservice, params)
        self.assertIsNone(check)

    def test_check_http_no_method(self):
        params = self.params_http
        del params['http_method']
        check = ServiceCheck.http(self.dummyservice, params)
        self.assertNotIn('Method', check)

    def test_check_http_no_body(self):
        params = self.params_http
        del params['body']
        check = ServiceCheck.http(self.dummyservice, params)
        self.assertNotIn('Body', check)

    def test_check_http_unsupported_body(self):
        ServiceCheck.consul_version = (1, 0, 0)
        params = self.params_http
        check = ServiceCheck.http(self.dummyservice, params)
        # body isn't supported, check should be None
        self.assertIsNone(check)

    def test_check_http_unsupported_method(self):
        ServiceCheck.consul_version = (0, 8, 4)
        params = self.params_http
        del params['body']
        check = ServiceCheck.http(self.dummyservice, params)
        # method isn't supported, check should be None
        self.assertIsNone(check)

    def test_check_http_invalid_header(self):
        params = self.params_http
        params['header'] = 'invalid_json'
        check = ServiceCheck.http(self.dummyservice, params)
        self.assertNotIn('header', check)

    def test_check_https(self):
        params = self.params_https
        check = ServiceCheck.https(self.dummyservice, params)
        self.assertEqual(check['http'], 'https://6.6.6.6:666/path')
        self.assertEqual(check['interval'], '17s')
        self.assertEqual(check['timeout'], '3s')
        self.assertEqual(check['header'], {'x-foo': ['bar', 'baz']})
        self.assertEqual(check['Method'], 'HEAD')
        self.assertEqual(check['Body'], params['body'])
        self.assertEqual(len(check), 6)

    def test_check_https_skip_verify_true(self):
        params = self.params_https
        params['tls_skip_verify'] = 'TrUe'
        check = ServiceCheck.https(self.dummyservice, params)
        self.assertIn('TLSSkipVerify', check)
        self.assertTrue(check['TLSSkipVerify'])

    def test_check_https_skip_verify_false(self):
        params = self.params_https
        params['tls_skip_verify'] = 'false'
        check = ServiceCheck.https(self.dummyservice, params)
        self.assertNotIn('TLSSkipVerify', check)


class TestServiceCheckTcp(unittest.TestCase):

    def setUp(self):
        ServiceCheck.consul_version = (1, 7, 0)
        self.dummyservice = DummyService()
        self.params_tcp = {
            'tcp': 'True',
            'interval': '17s',
            'timeout': '3s',
            'deregister': '666s',
        }

    def test_check_tcp(self):
        params = self.params_tcp
        check = ServiceCheck.tcp(self.dummyservice, params)
        self.assertEqual(check['tcp'], '6.6.6.6:666')
        self.assertEqual(check['interval'], '17s')
        self.assertEqual(check['timeout'], '3s')
        self.assertEqual(check['DeregisterCriticalServiceAfter'], '666s')
        self.assertEqual(len(check), 4)

    def test_check_tcp_false(self):
        params = self.params_tcp
        params['tcp'] = 'false'
        check = ServiceCheck.tcp(self.dummyservice, params)
        self.assertIsNone(check)


class TestServiceCheckTtl(unittest.TestCase):

    def setUp(self):
        ServiceCheck.consul_version = (1, 7, 0)
        self.dummyservice = DummyService()
        self.params_ttl = {
            'ttl': '17s',
        }

    def test_check_ttl(self):
        params = self.params_ttl
        check = ServiceCheck.ttl(self.dummyservice, params)
        self.assertEqual(check['ttl'], '17s')
        self.assertEqual(len(check), 1)

    def test_check_ttl_empty(self):
        params = self.params_ttl
        params['ttl'] = ''
        check = ServiceCheck.ttl(self.dummyservice, params)
        self.assertIsNone(check)


class TestServiceCheckScript(unittest.TestCase):

    def setUp(self):
        ServiceCheck.consul_version = (1, 7, 0)
        self.dummyservice = DummyService()
        self.params_script = {
            'script': 'command arg1 arg2',
            'interval': '5s',
        }

    def test_check_script(self):
        params = self.params_script
        check = ServiceCheck.script(self.dummyservice, params)
        self.assertEqual(check['args'], ['command', 'arg1', 'arg2'])
        self.assertEqual(check['interval'], '5s')
        self.assertEqual(len(check), 2)

    def test_check_script_replace(self):
        params = self.params_script
        params['script'] = 'command $SERVICE_IP:$SERVICE_PORT'
        check = ServiceCheck.script(self.dummyservice, params)
        self.assertEqual(check['args'], ['command', '6.6.6.6:666'])

    def test_check_script_empty(self):
        params = self.params_script
        params['script'] = ''
        check = ServiceCheck.script(self.dummyservice, params)
        self.assertIsNone(check)

    def test_check_script_consul_1(self):
        ServiceCheck.consul_version = (0, 9, 6)
        params = self.params_script
        with pytest.deprecated_call():
            check = ServiceCheck.script(self.dummyservice, params)
        self.assertEqual(check['script'], 'command arg1 arg2')
        self.assertEqual(check['interval'], '5s')
        self.assertEqual(len(check), 2)


class TestServiceCheckDocker(unittest.TestCase):

    def setUp(self):
        ServiceCheck.consul_version = (1, 7, 0)
        self.dummyservice = DummyService()
        self.params_docker = {
            'docker': 'command arg1 arg2',
            'interval': '5s',
            'shell': '/bin/sh',
        }

    def test_check_docker(self):
        params = self.params_docker
        check = ServiceCheck.docker(self.dummyservice, params)
        print(check)
        # {'docker_container_id': 'deadbeef', 'shell': '/bin/sh', 'interval': '5s', 'args': ['command', 'arg1', 'arg2']}
        self.assertEqual(check['args'], ['command', 'arg1', 'arg2'])
        self.assertEqual(check['docker_container_id'], 'deadbeef')
        self.assertEqual(check['shell'], '/bin/sh')
        self.assertEqual(check['interval'], '5s')
        self.assertEqual(len(check), 4)

    def test_check_docker_empty(self):
        params = self.params_docker
        params['docker'] = ''
        check = ServiceCheck.docker(self.dummyservice, params)
        self.assertIsNone(check)

    def test_check_docker_consul_1(self):
        ServiceCheck.consul_version = (0, 9, 6)
        params = self.params_docker
        check = ServiceCheck.docker(self.dummyservice, params)
        print(check)
        # {'docker_container_id': 'deadbeef', 'shell': '/bin/sh', 'interval': '5s', 'args': ['command', 'arg1', 'arg2']}
        self.assertEqual(check['script'], 'command arg1 arg2')
        self.assertEqual(check['docker_container_id'], 'deadbeef')
        self.assertEqual(check['shell'], '/bin/sh')
        self.assertEqual(check['interval'], '5s')
        self.assertEqual(len(check), 4)
