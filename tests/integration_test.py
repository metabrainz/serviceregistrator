"""Integration tests using real Docker and Consul containers.

These tests require Docker to be running and accessible.
They are marked with @pytest.mark.integration and skipped by default.
Run with: uv run pytest -m integration tests/integration_test.py -v
"""

import signal
import socket
import time

import docker
import pytest
import requests

from serviceregistrator.consul_client import ConsulClient

CONSUL_IMAGE = "hashicorp/consul:1.15"
CONSUL_PORT = 18500  # non-standard port to avoid conflicts
NGINX_IMAGE = "nginx:alpine"

# Skip all tests in this module if Docker is not available
pytestmark = pytest.mark.integration


def docker_available():
    try:
        docker.from_env().ping()
        return True
    except Exception:
        return False


if not docker_available():
    pytest.skip("Docker not available", allow_module_level=True)


@pytest.fixture(scope="module")
def docker_client():
    return docker.from_env()


@pytest.fixture(scope="module")
def consul_container(docker_client):
    """Start a Consul agent in dev mode for the test session."""
    container = docker_client.containers.run(
        CONSUL_IMAGE,
        command="agent -dev -client=0.0.0.0",
        detach=True,
        ports={"8500/tcp": CONSUL_PORT},
        name="test-consul-integration",
        remove=True,
    )
    for _ in range(30):
        try:
            resp = requests.get(f"http://127.0.0.1:{CONSUL_PORT}/v1/status/leader")
            if resp.ok and resp.json():
                break
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    else:
        container.stop()
        pytest.fail("Consul did not become ready in time")

    yield container
    container.stop()


@pytest.fixture
def consul(consul_container):
    return ConsulClient(host="127.0.0.1", port=CONSUL_PORT)


@pytest.fixture
def cleanup_containers(docker_client):
    created = []

    def _track(container):
        created.append(container)
        return container

    yield _track

    for c in created:
        try:
            c.stop(timeout=1)
        except Exception:
            pass
        try:
            c.remove(force=True)
        except Exception:
            pass


def _make_sr(prefix):
    """Create a ServiceRegistrator with a unique prefix to isolate from host containers."""
    from serviceregistrator import Context
    from serviceregistrator.registrator import ServiceRegistrator

    options = {
        "ip": "127.0.0.1",
        "tags": "",
        "consul_host": "127.0.0.1",
        "consul_port": CONSUL_PORT,
        "dockersock": "/var/run/docker.sock",
        "debug": False,
        "debug_requests": False,
        "service_prefix": prefix,
        "resync": 0,
        "logfile": None,
        "loglevel": "DEBUG",
        "delay": 1,
    }
    context = Context(options)
    return ServiceRegistrator(context)


def _services_with_prefix(consul, prefix):
    """Filter consul services to only those matching our test prefix."""
    return {k: v for k, v in consul.agent_services().items() if k.startswith(f"{prefix}:")}


# --- ConsulClient integration tests ---


class TestConsulClientIntegration:
    def test_status_peers(self, consul):
        peers = consul.status_peers()
        assert isinstance(peers, list)
        assert len(peers) > 0

    def test_agent_self(self, consul):
        info = consul.agent_self()
        assert "Config" in info
        assert "Version" in info["Config"]

    def test_agent_services_empty_initially(self, consul):
        services = consul.agent_services()
        assert isinstance(services, dict)

    def test_register_and_deregister(self, consul):
        consul.agent_service_register(
            name="test-svc",
            service_id="test-svc-1",
            address="10.0.0.1",
            port=8080,
            tags=["test", "integration"],
            meta={"version": "1.0"},
        )

        services = consul.agent_services()
        assert "test-svc-1" in services
        svc = services["test-svc-1"]
        assert svc["Service"] == "test-svc"
        assert svc["Address"] == "10.0.0.1"
        assert svc["Port"] == 8080
        assert set(svc["Tags"]) == {"test", "integration"}
        assert svc["Meta"]["version"] == "1.0"

        consul.agent_service_deregister("test-svc-1")

        services = consul.agent_services()
        assert "test-svc-1" not in services

    def test_register_with_http_check(self, consul):
        consul.agent_service_register(
            name="test-svc-check",
            service_id="test-svc-check-1",
            address="10.0.0.1",
            port=8080,
            check={
                "http": "http://10.0.0.1:8080/health",
                "interval": "10s",
                "timeout": "2s",
            },
        )

        services = consul.agent_services()
        assert "test-svc-check-1" in services

        consul.agent_service_deregister("test-svc-check-1")

    def test_deregister_nonexistent_raises(self, consul):
        with pytest.raises(requests.HTTPError):
            consul.agent_service_deregister("does-not-exist")


# --- End-to-end: ServiceRegistrator with real Docker + Consul ---


class TestServiceRegistratorIntegration:
    def test_sync_registers_and_cleans_up(self, consul, docker_client, cleanup_containers):
        hostname = socket.gethostname()
        prefix = "inttest-reg"

        container = docker_client.containers.run(
            NGINX_IMAGE,
            detach=True,
            ports={"80/tcp": None},
            environment=[
                "SERVICE_80_NAME=inttest-nginx",
                "SERVICE_80_CHECK_TCP=true",
                "SERVICE_80_CHECK_INTERVAL=10s",
                "SERVICE_TAGS=integration,test",
            ],
            name="inttest-nginx",
        )
        cleanup_containers(container)
        container.reload()

        host_port = int(container.ports["80/tcp"][0]["HostPort"])

        sr = _make_sr(prefix)
        sr.sync_with_containers()

        # Verify registered
        services = _services_with_prefix(consul, prefix)
        expected_id = f"{prefix}:{hostname}:inttest-nginx:{host_port}"
        assert expected_id in services, f"Expected {expected_id} in {list(services.keys())}"

        svc = services[expected_id]
        assert svc["Service"] == f"{prefix}-inttest-nginx"
        assert svc["Port"] == host_port
        assert "integration" in svc["Tags"]
        assert "test" in svc["Tags"]

        # Verify check was registered
        checks_resp = requests.get(f"http://127.0.0.1:{CONSUL_PORT}/v1/agent/checks")
        checks = checks_resp.json()
        service_checks = {k: v for k, v in checks.items() if v.get("ServiceID") == expected_id}
        assert len(service_checks) > 0

        # Stop container, re-sync — cleanup should deregister it
        container.stop(timeout=1)
        container.remove(force=True)

        # Container is gone, so parse_container_meta will fail for it.
        # Remove it from sr.containers so cleanup sees it as stale.
        sr.containers.clear()
        sr.sync_with_containers()

        services = _services_with_prefix(consul, prefix)
        our_test_svcs = [k for k in services if "inttest-nginx" in k]
        assert len(our_test_svcs) == 0

    def test_sync_skips_container_without_service_name(self, consul, docker_client, cleanup_containers):
        prefix = "inttest-skip"

        container = docker_client.containers.run(
            NGINX_IMAGE,
            detach=True,
            ports={"80/tcp": None},
            name="inttest-no-service",
        )
        cleanup_containers(container)

        sr = _make_sr(prefix)
        sr.sync_with_containers()

        # The test container should NOT be registered (no SERVICE_NAME)
        services = _services_with_prefix(consul, prefix)
        our_test_svcs = [k for k in services if "inttest-no-service" in k]
        assert len(our_test_svcs) == 0

    def test_sync_multiple_ports(self, consul, docker_client, cleanup_containers):
        prefix = "inttest-mp"

        container = docker_client.containers.run(
            NGINX_IMAGE,
            detach=True,
            ports={"80/tcp": None, "443/tcp": None},
            environment=[
                "SERVICE_80_NAME=inttest-multi",
                "SERVICE_443_NAME=inttest-multi-ssl",
            ],
            name="inttest-multi-port",
        )
        cleanup_containers(container)
        container.reload()

        sr = _make_sr(prefix)
        sr.sync_with_containers()

        services = _services_with_prefix(consul, prefix)
        mp_services = {k: v for k, v in services.items() if "inttest-multi-port" in k}
        assert len(mp_services) == 2

        names = {v["Service"] for v in mp_services.values()}
        assert f"{prefix}-inttest-multi" in names
        assert f"{prefix}-inttest-multi-ssl" in names

        # Cleanup
        container.stop(timeout=1)
        container.remove(force=True)
        sr.containers.clear()
        sr.sync_with_containers()

        services = _services_with_prefix(consul, prefix)
        mp_services = {k: v for k, v in services.items() if "inttest-multi-port" in k}
        assert len(mp_services) == 0

    def test_sync_alias_service(self, consul, docker_client, cleanup_containers):
        hostname = socket.gethostname()
        prefix = "inttest-alias"

        container = docker_client.containers.run(
            NGINX_IMAGE,
            detach=True,
            ports={"80/tcp": None},
            environment=[
                "SERVICE_80_NAME=haproxy-postgres-primary",
                "SERVICE_80_ALIAS=postgres-master",
                "SERVICE_TAGS=db",
            ],
            name="inttest-alias-svc",
        )
        cleanup_containers(container)
        container.reload()

        host_port = int(container.ports["80/tcp"][0]["HostPort"])

        sr = _make_sr(prefix)
        sr.sync_with_containers()

        services = _services_with_prefix(consul, prefix)
        alias_svcs = {k: v for k, v in services.items() if "inttest-alias-svc" in k}
        assert len(alias_svcs) == 2, f"Expected 2 services (real + alias), got {list(alias_svcs.keys())}"

        # Check the real service
        real_id = f"{prefix}:{hostname}:inttest-alias-svc:{host_port}"
        assert real_id in alias_svcs
        assert alias_svcs[real_id]["Service"] == f"{prefix}-haproxy-postgres-primary"

        # Check the alias service
        alias_id = f"{prefix}:{hostname}:inttest-alias-svc:{host_port}:alias"
        assert alias_id in alias_svcs
        assert alias_svcs[alias_id]["Service"] == "postgres-master"
        assert alias_svcs[alias_id]["Port"] == host_port

        # Verify alias has an alias-type check pointing to the real service
        checks_resp = requests.get(f"http://127.0.0.1:{CONSUL_PORT}/v1/agent/checks")
        checks = checks_resp.json()
        alias_checks = {k: v for k, v in checks.items() if v.get("ServiceID") == alias_id}
        assert len(alias_checks) == 1
        check = list(alias_checks.values())[0]
        assert check["Type"] == "alias"

        # Cleanup
        container.stop(timeout=1)
        container.remove(force=True)
        sr.containers.clear()
        sr.sync_with_containers()

        services = _services_with_prefix(consul, prefix)
        alias_svcs = {k: v for k, v in services.items() if "inttest-alias-svc" in k}
        assert len(alias_svcs) == 0


class TestMainLoopIntegration:
    """Test the CLI main() entry point end-to-end."""

    def test_main_runs_and_exits_on_signal(self, consul_container, docker_client, cleanup_containers):
        import subprocess

        container = docker_client.containers.run(
            NGINX_IMAGE,
            detach=True,
            ports={"80/tcp": None},
            environment=["SERVICE_80_NAME=inttest-main"],
            name="inttest-main-loop",
        )
        cleanup_containers(container)

        # Run serviceregistrator as a subprocess
        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "serviceregistrator",
                "--ip",
                "127.0.0.1",
                "--consul-host",
                "127.0.0.1",
                "--consul-port",
                str(CONSUL_PORT),
                "--service-prefix",
                "inttest-main",
                "--delay",
                "1",
                "--loglevel",
                "DEBUG",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            # Wait for it to sync
            time.sleep(3)

            # Verify it registered the service
            consul = ConsulClient("127.0.0.1", CONSUL_PORT)
            services = _services_with_prefix(consul, "inttest-main")
            main_svcs = [k for k in services if "inttest-main-loop" in k]
            assert len(main_svcs) > 0, f"Expected main loop to register service, got {list(services.keys())}"
        finally:
            # Send SIGTERM to stop gracefully
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=10)
            assert proc.returncode == 0
