#  ServiceRegistrator is a service registry bridge between Docker and Consul
#
#    Copyright (C) 2021 Laurent Monin
#    Copyright (C) 2021 MetaBrainz Foundation
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Minimal Consul HTTP API client, replacing python-consul2."""

import logging

import requests

log = logging.getLogger("serviceregistrator")


class ConsulAPIError(Exception):
    pass


class ConsulClient:
    def __init__(self, host="127.0.0.1", port=8500):
        self.base_url = f"http://{host}:{port}/v1"

    def _request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        resp = requests.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp

    def status_peers(self):
        return self._request("GET", "/status/peers").json()

    def agent_self(self):
        return self._request("GET", "/agent/self").json()

    def agent_services(self):
        return self._request("GET", "/agent/services").json()

    def agent_service_register(self, name, service_id, address, port, tags=None, meta=None, check=None):
        payload = {
            "Name": name,
            "ID": service_id,
            "Address": address,
            "Port": port,
        }
        if tags:
            payload["Tags"] = tags
        if meta:
            payload["Meta"] = meta
        if check:
            payload["Check"] = check
        self._request("PUT", "/agent/service/register", json=payload)

    def agent_service_deregister(self, service_id):
        self._request("PUT", f"/agent/service/deregister/{service_id}")
