import unittest
from unittest.mock import patch, Mock, PropertyMock
from click.testing import CliRunner
from serviceregistrator.main import main


class TestMainCli(unittest.TestCase):

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'Register docker containers as consul services' in result.output

    def test_missing_required_ip(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code != 0
        assert 'Missing option' in result.output or 'required' in result.output.lower()

    def test_bad_dockersock(self):
        runner = CliRunner()
        result = runner.invoke(main, ['--ip', '127.0.0.1', '--dockersock', '/nonexistent/sock'])
        # Should exit quickly because the socket doesn't exist
        assert result.exit_code == 0  # click doesn't fail, the app sets kill_now

    def test_invalid_loglevel_rejected(self):
        runner = CliRunner()
        result = runner.invoke(main, ['--ip', '127.0.0.1', '--loglevel', 'BOGUS'])
        assert result.exit_code != 0
