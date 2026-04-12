import unittest
from unittest.mock import Mock, patch

import requests

from serviceregistrator.registrator import (
    ServiceRegistrator,
    ConsulConnectionError,
    Ports,
    my_default_user_agent,
)
from serviceregistrator.service import Service


def make_registrator(**ctx_overrides):
    """Create a ServiceRegistrator with mocked consul/docker init."""
    with patch.object(ServiceRegistrator, "_init_consul"), patch.object(ServiceRegistrator, "_init_docker"):
        context = Mock()
        context.options = {
            "debug": False,
            "tags": "",
            "ip": "127.0.0.1",
            "service_prefix": None,
            "consul_host": "127.0.0.1",
            "consul_port": 8500,
            "dockersock": "/var/run/docker.sock",
        }
        context.options.update(ctx_overrides)
        context.containers = {}
        context.kill_now = False
        sr = ServiceRegistrator(context)
        sr.hostname = "testhost"
        sr.consul_client = Mock()
        sr.docker_client = Mock()
        return sr


class TestConsulConnectionError(unittest.TestCase):
    def test_message(self):
        e = ConsulConnectionError("timeout")
        assert "Consul connection error" in str(e)
        assert "timeout" in str(e)


class TestUserAgent(unittest.TestCase):
    def test_user_agent_returns_string(self):
        import serviceregistrator.registrator as mod

        mod._USER_AGENT = None
        ua = my_default_user_agent()
        assert "ServiceRegistrator" in ua
        # Second call uses cached value
        ua2 = my_default_user_agent()
        assert ua == ua2


class TestFmtEvent(unittest.TestCase):
    def test_fmtevent(self):
        result = ServiceRegistrator.fmtevent("start", "container", "abc123")
        assert "start" in result
        assert "container" in result
        assert "abc123" in result


class TestParseTagsString(unittest.TestCase):
    def test_valid_tags(self):
        container = Mock()
        result = ServiceRegistrator.parse_tags_string(container, "tag1,tag2,tag3")
        assert result == ["tag1", "tag2", "tag3"]

    def test_empty_string(self):
        container = Mock()
        result = ServiceRegistrator.parse_tags_string(container, "")
        assert result == []

    def test_invalid_tag(self):
        container = Mock()
        result = ServiceRegistrator.parse_tags_string(container, "valid,inv@lid,ok")
        assert "valid" in result
        assert "ok" in result
        assert "inv@lid" not in result

    def test_whitespace_trimmed(self):
        container = Mock()
        result = ServiceRegistrator.parse_tags_string(container, " tag1 , tag2 ")
        assert "tag1" in result
        assert "tag2" in result

    def test_dedup(self):
        container = Mock()
        result = ServiceRegistrator.parse_tags_string(container, "a,a,b")
        assert len(result) == 2


class TestMakeCheck(unittest.TestCase):
    def test_no_check_attrs(self):
        service = Mock()
        service.attrs = {"region": "us-east"}
        result = ServiceRegistrator.make_check(service)
        assert result is None

    def test_http_check(self):
        service = Service(
            "cid", "sid", "sname", "1.2.3.4", 80, tags=[], attrs={"check_http": "/health", "check_interval": "10s"}
        )
        from serviceregistrator.servicecheck import ServiceCheck

        ServiceCheck.consul_version = (1, 7, 0)
        result = ServiceRegistrator.make_check(service)
        assert result is not None
        assert "http" in result

    def test_check_exception(self):
        service = Mock()
        service.attrs = {"check_http": "/health"}
        service.id = "sid"
        # Force an exception in the check function
        with patch("serviceregistrator.servicecheck.ServiceCheck.http", side_effect=Exception("boom")):
            result = ServiceRegistrator.make_check(service)
        assert result is None


class TestServiceMeta(unittest.TestCase):
    def test_filters_check_and_ip(self):
        service = Mock()
        service.attrs = {
            "check_http": "/health",
            "check_interval": "10s",
            "ip": "1.2.3.4",
            "region": "us-east",
            "version": "1.0",
        }
        result = ServiceRegistrator.service_meta(service)
        assert result == {"region": "us-east", "version": "1.0"}


class TestWatchEvents(unittest.TestCase):
    def _make_event(self, action="start", etype="container", cid="abc123"):
        return {"Action": action, "Type": etype, "Actor": {"ID": cid}}

    def test_kill_now_breaks(self):
        sr = make_registrator()
        sr.context.kill_now = True
        sr.events = [self._make_event()]
        sr.watch_events()
        # Should exit immediately

    def test_syncing_skips_events(self):
        sr = make_registrator(debug=True)
        sr.syncing = True
        sr.events = [self._make_event()]
        sr.context.kill_now = False
        # After processing the event list is exhausted, loop ends
        sr.watch_events()

    def test_non_container_event_skipped(self):
        sr = make_registrator(debug=True)
        sr.events = [self._make_event(etype="network")]
        sr.watch_events()

    def test_unhandled_action_skipped(self):
        sr = make_registrator(debug=True)
        sr.events = [self._make_event(action="create")]
        sr.watch_events()

    def test_register_action(self):
        sr = make_registrator()
        container_info = Mock()
        container_info.__bool__ = Mock(return_value=True)
        sr.parse_container_meta = Mock(return_value=container_info)
        sr.register_container = Mock()
        sr.events = [self._make_event(action="start")]
        sr.watch_events()
        sr.register_container.assert_called_once_with(container_info)

    def test_unregister_action(self):
        sr = make_registrator()
        container_info = Mock()
        container_info.__bool__ = Mock(return_value=True)
        sr.parse_container_meta = Mock(return_value=container_info)
        sr.unregister_container = Mock()
        sr.events = [self._make_event(action="die")]
        sr.watch_events()
        sr.unregister_container.assert_called_once_with(container_info)

    def test_no_container_info_skipped(self):
        sr = make_registrator(debug=True)
        sr.parse_container_meta = Mock(return_value=None)
        sr.register_container = Mock()
        sr.events = [self._make_event(action="start")]
        sr.watch_events()
        sr.register_container.assert_not_called()


class TestParseContainerMeta(unittest.TestCase):
    def test_no_service_metadata(self):
        sr = make_registrator()
        container = Mock()
        container.attrs = {"Config": {"Env": []}}
        container.labels = {}
        sr.docker_get_container_by_id = Mock(return_value=container)
        result = sr.parse_container_meta("cid123")
        assert result is None

    def test_no_ports(self):
        sr = make_registrator()
        container = Mock()
        container.attrs = {
            "Config": {"Env": ["SERVICE_NAME=myservice"]},
            "HostConfig": {"NetworkMode": "other"},
        }
        container.labels = {}
        container.name = "test"
        sr.docker_get_container_by_id = Mock(return_value=container)
        result = sr.parse_container_meta("cid123")
        assert result is None

    def test_extract_ports_exception(self):
        sr = make_registrator()
        container = Mock()
        container.attrs = {"Config": {"Env": ["SERVICE_NAME=myservice"]}}
        container.labels = {}
        sr.docker_get_container_by_id = Mock(return_value=container)
        sr.extract_ports = Mock(side_effect=Exception("bad"))
        result = sr.parse_container_meta("cid123")
        assert result is None

    def test_success_with_health(self):
        sr = make_registrator()
        container = Mock()
        container.attrs = {
            "Config": {"Env": ["SERVICE_NAME=myservice"]},
            "HostConfig": {"NetworkMode": "host"},
        }
        container.labels = {}
        container.name = "testcontainer"
        container.health = "healthy"
        ports = [Ports(internal=80, external=80, protocol="tcp", ip="0.0.0.0")]
        sr.docker_get_container_by_id = Mock(return_value=container)
        sr.extract_ports = Mock(return_value=ports)
        result = sr.parse_container_meta("cid123")
        assert result is not None
        assert result.health == "healthy"

    def test_success_no_health(self):
        sr = make_registrator()
        container = Mock()
        container.attrs = {
            "Config": {"Env": ["SERVICE_NAME=myservice"]},
            "HostConfig": {"NetworkMode": "host"},
        }
        container.labels = {}
        container.name = "testcontainer"
        container.health = "none"
        ports = [Ports(internal=80, external=80, protocol="tcp", ip="0.0.0.0")]
        sr.docker_get_container_by_id = Mock(return_value=container)
        sr.extract_ports = Mock(return_value=ports)
        result = sr.parse_container_meta("cid123")
        assert result is not None
        assert result.health is None

    def test_with_service_prefix(self):
        sr = make_registrator(service_prefix="test")
        container = Mock()
        container.attrs = {
            "Config": {"Env": ["SERVICE_NAME=myservice"]},
            "HostConfig": {"NetworkMode": "host"},
        }
        container.labels = {}
        container.name = "testcontainer"
        container.health = "none"
        ports = [Ports(internal=80, external=80, protocol="tcp", ip="0.0.0.0")]
        sr.docker_get_container_by_id = Mock(return_value=container)
        sr.extract_ports = Mock(return_value=ports)
        result = sr.parse_container_meta("cid123")
        assert result.service_prefix == "test"


class TestRegisterUnregisterContainer(unittest.TestCase):
    def test_register_healthy(self):
        sr = make_registrator()
        ci = Mock()
        ci.cid = "cid1"
        ci.health = None
        ci.services = []
        sr.register_container(ci)
        assert ci.cid in sr.containers

    def test_register_unhealthy_skipped(self):
        sr = make_registrator()
        ci = Mock()
        ci.cid = "cid1"
        ci.health = "unhealthy"
        sr.register_container(ci)
        assert ci.cid not in sr.containers

    def test_register_explicitly_healthy(self):
        sr = make_registrator()
        ci = Mock()
        ci.cid = "cid1"
        ci.health = "healthy"
        ci.services = []
        sr.register_container(ci)
        assert ci.cid in sr.containers

    def test_unregister_known_container(self):
        sr = make_registrator()
        ci = Mock()
        ci.cid = "cid1"
        ci.services = []
        sr.containers["cid1"] = ci
        sr.unregister_container(ci)
        assert "cid1" not in sr.containers

    def test_unregister_unknown_container(self):
        sr = make_registrator()
        ci = Mock()
        ci.cid = "unknown"
        ci.services = []
        # Should not raise
        sr.unregister_container(ci)


class TestConsulRegisterService(unittest.TestCase):
    def test_register_success(self):
        sr = make_registrator()
        service = Service("cid", "sid", "sname", "1.2.3.4", 80, tags=[], attrs={})
        sr.consul_register_service(service)
        sr.consul_client.agent_service_register.assert_called_once()

    def test_register_connection_error(self):
        sr = make_registrator()
        service = Service("cid", "sid", "sname", "1.2.3.4", 80, tags=[], attrs={})
        from requests.exceptions import ConnectionError

        sr.consul_client.agent_service_register.side_effect = ConnectionError("fail")
        with self.assertRaises(ConsulConnectionError):
            sr.consul_register_service(service)

    def test_register_other_exception(self):
        sr = make_registrator()
        service = Service("cid", "sid", "sname", "1.2.3.4", 80, tags=[], attrs={})
        sr.consul_client.agent_service_register.side_effect = Exception("fail")
        # Should not raise, just log
        sr.consul_register_service(service)


class TestConsulUnregisterService(unittest.TestCase):
    def test_unregister_service_object(self):
        sr = make_registrator()
        service = Service("cid", "sid", "sname", "1.2.3.4", 80, tags=[], attrs={})
        sr.consul_unregister_service(service)
        sr.consul_client.agent_service_deregister.assert_called_once_with("sid")

    def test_unregister_string_id(self):
        sr = make_registrator()
        sr.consul_unregister_service("some-service-id")
        sr.consul_client.agent_service_deregister.assert_called_once_with("some-service-id")

    def test_unregister_connection_error(self):
        sr = make_registrator()
        from requests.exceptions import ConnectionError

        sr.consul_client.agent_service_deregister.side_effect = ConnectionError("fail")
        with self.assertRaises(ConsulConnectionError):
            sr.consul_unregister_service("sid")

    def test_unregister_other_exception(self):
        sr = make_registrator()
        sr.consul_client.agent_service_deregister.side_effect = Exception("fail")
        sr.consul_unregister_service("sid")


class TestSyncWithContainers(unittest.TestCase):
    def test_already_syncing(self):
        sr = make_registrator()
        sr.syncing = True
        sr.docker_running_containers = Mock()
        sr.sync_with_containers()
        sr.docker_running_containers.assert_not_called()

    def test_sync_registers_containers(self):
        sr = make_registrator()
        container = Mock()
        container.id = "cid1"
        sr.docker_running_containers = Mock(return_value=[container])
        ci = Mock()
        ci.cid = "cid1"
        ci.health = None
        ci.services = []
        ci.__bool__ = Mock(return_value=True)
        sr.parse_container_meta = Mock(return_value=ci)
        sr.cleanup = Mock()
        sr.sync_with_containers()
        assert sr.syncing is False
        sr.cleanup.assert_called_once()

    def test_sync_skips_none_container_info(self):
        sr = make_registrator()
        container = Mock()
        container.id = "cid1"
        sr.docker_running_containers = Mock(return_value=[container])
        sr.parse_container_meta = Mock(return_value=None)
        sr.cleanup = Mock()
        sr.sync_with_containers()
        assert sr.syncing is False

    def test_sync_skips_falsy_container_info(self):
        sr = make_registrator()
        container = Mock()
        container.id = "cid1"
        sr.docker_running_containers = Mock(return_value=[container])
        ci = Mock()
        ci.__bool__ = Mock(return_value=False)
        sr.parse_container_meta = Mock(return_value=ci)
        sr.cleanup = Mock()
        sr.register_container = Mock()
        sr.sync_with_containers()
        sr.register_container.assert_not_called()


class TestCleanup(unittest.TestCase):
    def test_cleanup_removes_stale_services(self):
        sr = make_registrator()
        stale_id = "testhost:oldcontainer:8080"
        sr.consul_client.agent_services.return_value = {stale_id: {}}
        sr.consul_unregister_service = Mock()
        sr.cleanup()
        sr.consul_unregister_service.assert_called_once_with(stale_id)

    def test_cleanup_keeps_active_services(self):
        sr = make_registrator()
        active_id = "testhost:mycontainer:8080"
        sr.consul_client.agent_services.return_value = {active_id: {}}
        ci = Mock()
        ci.service_identifiers.return_value = [active_id]
        sr.containers["cid1"] = ci
        sr.consul_unregister_service = Mock()
        sr.cleanup()
        sr.consul_unregister_service.assert_not_called()

    def test_cleanup_skips_foreign_services(self):
        sr = make_registrator()
        sr.consul_client.agent_services.return_value = {"otherhost:svc:80": {}}
        sr.consul_unregister_service = Mock()
        sr.cleanup()
        sr.consul_unregister_service.assert_not_called()

    def test_cleanup_with_prefix(self):
        sr = make_registrator(service_prefix="pfx")
        stale_id = "pfx:testhost:oldcontainer:8080"
        sr.consul_client.agent_services.return_value = {stale_id: {}}
        sr.consul_unregister_service = Mock()
        sr.cleanup()
        sr.consul_unregister_service.assert_called_once_with(stale_id)


class TestConsulServices(unittest.TestCase):
    def test_success(self):
        sr = make_registrator()
        sr.consul_client.agent_services.return_value = {"svc1": {}}
        result = sr.consul_services()
        assert result == {"svc1": {}}

    def test_connection_error(self):
        sr = make_registrator()
        from requests.exceptions import ConnectionError

        sr.consul_client.agent_services.side_effect = ConnectionError("fail")
        with self.assertRaises(ConsulConnectionError):
            sr.consul_services()

    def test_other_exception(self):
        sr = make_registrator()
        sr.consul_client.agent_services.side_effect = Exception("fail")
        result = sr.consul_services()
        assert result == {}


class TestContainersServiceIdentifiers(unittest.TestCase):
    def test_aggregates_identifiers(self):
        sr = make_registrator()
        ci1 = Mock()
        ci1.service_identifiers.return_value = ["id1", "id2"]
        ci2 = Mock()
        ci2.service_identifiers.return_value = ["id3"]
        sr.containers = {"c1": ci1, "c2": ci2}
        result = sr.containers_service_identifiers()
        assert result == {"id1", "id2", "id3"}

    def test_empty(self):
        sr = make_registrator()
        result = sr.containers_service_identifiers()
        assert result == set()


class TestInitConsul(unittest.TestCase):
    def test_init_consul_success(self):
        sr = make_registrator()
        mock_client = Mock()
        mock_client.status_peers.return_value = ["127.0.0.1:8300"]
        mock_client.agent_self.return_value = {"Config": {"Version": "1.9.5"}}
        with patch("serviceregistrator.registrator.ConsulClient", return_value=mock_client):
            sr._init_consul()
        assert sr.consul_version == "1.9.5"
        from serviceregistrator.servicecheck import ServiceCheck

        assert ServiceCheck.consul_version == (1, 9, 5)

    def test_init_consul_connection_error(self):
        sr = make_registrator()
        from requests.exceptions import ConnectionError

        with patch("serviceregistrator.registrator.ConsulClient", side_effect=ConnectionError("fail")):
            with self.assertRaises(ConsulConnectionError):
                sr._init_consul()

    def test_init_consul_http_error(self):
        sr = make_registrator()
        mock_client = Mock()
        mock_client.status_peers.side_effect = requests.HTTPError("fail")
        with patch("serviceregistrator.registrator.ConsulClient", return_value=mock_client):
            with self.assertRaises(ConsulConnectionError):
                sr._init_consul()


class TestInitDocker(unittest.TestCase):
    def test_init_docker(self):
        sr = make_registrator()
        mock_client = Mock()
        mock_api = Mock()
        with (
            patch("serviceregistrator.registrator.docker.from_env", return_value=mock_client),
            patch("serviceregistrator.registrator.docker.APIClient", return_value=mock_api),
        ):
            sr._init_docker()
        assert sr.docker_client is mock_client
        assert sr.docker_api_client is mock_api
        # Verify close_events was registered
        sr.context.register_on_exit.assert_called()


class TestParseServiceMetaValidation(unittest.TestCase):
    def test_invalid_service_name_ignored(self):
        container = Mock()
        container.attrs = {"Config": {"Env": ["SERVICE_NAME=inv@lid!"]}}
        container.labels = {}
        metadata, _ = ServiceRegistrator.parse_service_meta(container)
        assert "name" not in metadata

    def test_valid_service_name(self):
        container = Mock()
        container.attrs = {"Config": {"Env": ["SERVICE_NAME=valid-name_1"]}}
        container.labels = {}
        metadata, _ = ServiceRegistrator.parse_service_meta(container)
        assert metadata["name"] == "valid-name_1"

    def test_env_overrides_labels(self):
        container = Mock()
        container.attrs = {"Config": {"Env": ["SERVICE_NAME=from_env"]}}
        container.labels = {"SERVICE_NAME": "from_label"}
        metadata, _ = ServiceRegistrator.parse_service_meta(container)
        assert metadata["name"] == "from_env"
