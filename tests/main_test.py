import unittest
from click.testing import CliRunner
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
