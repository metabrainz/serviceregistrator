import unittest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
import docker.errors
from serviceregistrator.main import main, loglevelfmt, validate_ip


class TestLogLevelFmt(unittest.TestCase):
    def test_uppercases_value(self):
        assert loglevelfmt(None, None, "debug") == "DEBUG"

    def test_none_returns_none(self):
        assert loglevelfmt(None, None, None) is None


class TestValidateIp(unittest.TestCase):
    def test_valid_ipv4(self):
        assert validate_ip(None, None, "127.0.0.1") == "127.0.0.1"

    def test_valid_ipv6(self):
        assert validate_ip(None, None, "::1") == "::1"

    def test_invalid_ip(self):
        import click

        with self.assertRaises(click.exceptions.BadParameter):
            validate_ip(None, None, "not-an-ip")


class TestMainCli(unittest.TestCase):
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Register docker containers as consul services" in result.output

    def test_missing_required_ip(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_bad_dockersock(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--ip", "127.0.0.1", "--dockersock", "/nonexistent/sock"])
        # Should exit quickly because the socket doesn't exist
        assert result.exit_code == 0  # click doesn't fail, the app sets kill_now

    def test_invalid_loglevel_rejected(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--ip", "127.0.0.1", "--loglevel", "BOGUS"])
        assert result.exit_code != 0

    def test_invalid_ip_rejected(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--ip", "not-an-ip"])
        assert result.exit_code != 0
        assert "invalid IP address" in result.output


class TestStaleDockerSocketDetection(unittest.TestCase):
    @patch("serviceregistrator.main.ServiceRegistrator")
    @patch("serviceregistrator.main.sleep")
    @patch("os.stat")
    def test_exits_after_consecutive_docker_failures(self, mock_stat, mock_sleep, mock_sr_class):
        import stat as stat_mod

        mock_stat_result = MagicMock()
        mock_stat_result.st_mode = stat_mod.S_IFSOCK | 0o660
        mock_stat.return_value = mock_stat_result

        mock_sr_class.side_effect = docker.errors.DockerException("Error while fetching server API version")

        runner = CliRunner()
        result = runner.invoke(main, ["--ip", "127.0.0.1", "--dockersock", "/var/run/docker.sock"])

        assert result.exit_code == 0
        assert "Docker connection failed 10 consecutive times" in result.output or mock_sr_class.call_count == 10

    @patch("serviceregistrator.main.ServiceRegistrator")
    @patch("serviceregistrator.main.sleep")
    @patch("os.stat")
    def test_resets_counter_on_successful_connection(self, mock_stat, mock_sleep, mock_sr_class):
        import stat as stat_mod

        mock_stat_result = MagicMock()
        mock_stat_result.st_mode = stat_mod.S_IFSOCK | 0o660
        mock_stat.return_value = mock_stat_result

        call_count = [0]

        def side_effect(context):
            call_count[0] += 1
            if call_count[0] <= 5:
                raise docker.errors.DockerException("Connection refused")
            if call_count[0] == 6:
                # Succeed on 6th call, resets counter; watch_events fails (counts as failure 1)
                mock_instance = MagicMock()
                mock_instance.sync_with_containers.return_value = None
                mock_instance.watch_events.side_effect = docker.errors.DockerException("lost connection")
                return mock_instance
            # All subsequent constructor calls fail
            raise docker.errors.DockerException("Connection refused")

        mock_sr_class.side_effect = side_effect

        runner = CliRunner()
        result = runner.invoke(main, ["--ip", "127.0.0.1", "--dockersock", "/var/run/docker.sock"])

        assert result.exit_code == 0
        # 5 constructor failures + 1 success (resets counter, watch_events fails = failure 1)
        # + 9 more constructor failures (failures 2-10) = 15 total calls
        assert mock_sr_class.call_count == 15
