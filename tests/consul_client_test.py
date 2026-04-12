import unittest
from unittest.mock import patch, Mock

from serviceregistrator.consul_client import ConsulClient


def _mock_response(json_data=None, status_code=200):
    resp = Mock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestConsulClient(unittest.TestCase):
    def setUp(self):
        self.client = ConsulClient(host="10.0.0.1", port=8500)

    @patch("serviceregistrator.consul_client.requests.request")
    def test_status_peers(self, mock_req):
        mock_req.return_value = _mock_response(["10.0.0.1:8300"])
        result = self.client.status_peers()
        assert result == ["10.0.0.1:8300"]
        mock_req.assert_called_once_with("GET", "http://10.0.0.1:8500/v1/status/peers", timeout=30)

    @patch("serviceregistrator.consul_client.requests.request")
    def test_agent_self(self, mock_req):
        mock_req.return_value = _mock_response({"Config": {"Version": "1.15.0"}})
        result = self.client.agent_self()
        assert result["Config"]["Version"] == "1.15.0"

    @patch("serviceregistrator.consul_client.requests.request")
    def test_agent_services(self, mock_req):
        mock_req.return_value = _mock_response({"svc-1": {"Service": "web"}})
        result = self.client.agent_services()
        assert "svc-1" in result

    @patch("serviceregistrator.consul_client.requests.request")
    def test_agent_service_register(self, mock_req):
        mock_req.return_value = _mock_response()
        self.client.agent_service_register(
            name="web",
            service_id="web-1",
            address="10.0.0.1",
            port=8080,
            tags=["prod"],
            meta={"v": "1"},
            check={"tcp": "10.0.0.1:8080", "interval": "10s"},
        )
        call_kwargs = mock_req.call_args
        payload = call_kwargs.kwargs["json"]
        assert payload["Name"] == "web"
        assert payload["Tags"] == ["prod"]
        assert payload["Meta"] == {"v": "1"}
        assert "Check" in payload

    @patch("serviceregistrator.consul_client.requests.request")
    def test_agent_service_register_minimal(self, mock_req):
        mock_req.return_value = _mock_response()
        self.client.agent_service_register(name="web", service_id="web-1", address="10.0.0.1", port=8080)
        payload = mock_req.call_args.kwargs["json"]
        assert "Tags" not in payload
        assert "Meta" not in payload
        assert "Check" not in payload

    @patch("serviceregistrator.consul_client.requests.request")
    def test_agent_service_deregister(self, mock_req):
        mock_req.return_value = _mock_response()
        self.client.agent_service_deregister("web-1")
        mock_req.assert_called_once_with("PUT", "http://10.0.0.1:8500/v1/agent/service/deregister/web-1", timeout=30)

    @patch("serviceregistrator.consul_client.requests.request")
    def test_request_raises_on_http_error(self, mock_req):
        import requests

        resp = Mock()
        resp.raise_for_status.side_effect = requests.HTTPError("500")
        mock_req.return_value = resp
        with self.assertRaises(requests.HTTPError):
            self.client.status_peers()

    @patch("serviceregistrator.consul_client.requests.request")
    def test_timeout_default(self, mock_req):
        mock_req.return_value = _mock_response([])
        self.client.status_peers()
        assert mock_req.call_args.kwargs["timeout"] == 30
