#  ServiceRegistrator is a service registry bridge between Docker and Consul
#
#    It is a stripped-down Python re-implementation of Gliderlabs Registrator,
#    partly compatible with its SERVICE_* syntax.
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

import json
import logging
import shlex
from typing import Any

from serviceregistrator.service import Service

log = logging.getLogger("serviceregistrator")


def _build_check(**kwargs: Any) -> dict[str, Any]:
    """Build a check dict, omitting None values."""
    return {k: v for k, v in kwargs.items() if v is not None}


class ServiceCheck:
    defaults: dict[str, Any] = {
        "body": None,
        "deregister": None,
        "docker": None,
        "header": None,
        "http": "",
        "https": "",
        "http_method": None,
        "https_method": None,
        "initial_status": None,
        "interval": "10s",
        "shell": "/bin/sh",
        "script": None,
        "tcp": None,
        "timeout": None,
        "tls_skip_verify": None,
        "ttl": None,
    }

    consul_version: tuple[int, ...] = (0, 0, 0)

    @classmethod
    def _value(cls, params: dict[str, str], key: str) -> Any:
        return params.get(key, cls.defaults.get(key))

    @classmethod
    def _common_values(cls, params: dict[str, str]) -> tuple[Any, Any]:
        interval = cls._value(params, "interval")
        deregister = cls._value(params, "deregister")
        return interval, deregister

    @classmethod
    def _json_value(cls, params: dict[str, str], key: str) -> Any:
        value = cls._value(params, key)
        if value:
            try:
                return json.loads(value)
            except Exception as e:
                log.error(e)
        return None

    @classmethod
    def _bool_value(cls, params: dict[str, str], key: str) -> bool:
        value = cls._value(params, key)
        return bool(value and value.lower() == "true")

    @classmethod
    def _post_process(cls, checkret: dict[str, Any], params: dict[str, str]) -> dict[str, Any]:
        # https://developer.hashicorp.com/consul/api-docs/agent/check#status
        initial_status = cls._value(params, "initial_status")
        if initial_status:
            checkret["Status"] = initial_status
        return checkret

    @classmethod
    def _http(cls, service: Service, params: dict[str, str], proto: str = "http") -> dict[str, Any] | None:
        """
        Consul HTTP/HTTPS Check

        SERVICE_80_CHECK_HTTP=/health/endpoint/path
        SERVICE_80_CHECK_INTERVAL=15s
        SERVICE_80_CHECK_TIMEOUT=1s

        SERVICE_443_CHECK_HTTPS=/health/endpoint/path
        SERVICE_443_CHECK_INTERVAL=15s
        SERVICE_443_CHECK_TIMEOUT=1s
        """
        # https://developer.hashicorp.com/consul/docs/discovery/checks#http-interval
        path = cls._value(params, proto)
        if path:
            url = f"{proto}://{service.ip}:{service.port}{path}"
            timeout = cls._value(params, "timeout")
            interval, deregister = cls._common_values(params)
            tls_skip_verify = cls._bool_value(params, "tls_skip_verify")
            header = cls._json_value(params, "header")
            ret = _build_check(
                http=url,
                interval=interval,
                timeout=timeout,
                DeregisterCriticalServiceAfter=deregister,
                header=header,
                TLSSkipVerify=tls_skip_verify or None,
            )
            method = cls._value(params, proto + "_method")
            if method:
                ret["Method"] = method.upper()
            body = cls._value(params, "body")
            if body:
                ret["Body"] = body
            return cls._post_process(ret, params)
        return None

    @classmethod
    def http(cls, service: Service, params: dict[str, str]) -> dict[str, Any] | None:
        return cls._http(service, params, proto="http")

    @classmethod
    def https(cls, service: Service, params: dict[str, str]) -> dict[str, Any] | None:
        return cls._http(service, params, proto="https")

    @classmethod
    def tcp(cls, service: Service, params: dict[str, str]) -> dict[str, Any] | None:
        """
        Consul TCP Check

        SERVICE_443_CHECK_TCP=true
        SERVICE_443_CHECK_INTERVAL=15s
        SERVICE_443_CHECK_TIMEOUT=3s
        """
        # https://developer.hashicorp.com/consul/docs/discovery/checks#tcp-interval
        tcp = cls._bool_value(params, "tcp")
        if tcp:
            host = service.ip
            port = service.port
            interval, deregister = cls._common_values(params)
            timeout = cls._value(params, "timeout")
            ret = _build_check(
                tcp=f"{host}:{port}",
                interval=interval,
                timeout=timeout,
                DeregisterCriticalServiceAfter=deregister,
            )
            return cls._post_process(ret, params)
        return None

    @classmethod
    def ttl(cls, service: Service, params: dict[str, str]) -> dict[str, Any] | None:
        """
        Consul TTL Check

        SERVICE_CHECK_TTL=30s
        """
        # https://developer.hashicorp.com/consul/docs/discovery/checks#ttl
        ttl = cls._value(params, "ttl")
        if ttl:
            ret = {"ttl": ttl}
            return cls._post_process(ret, params)
        return None

    @classmethod
    def script(cls, service: Service, params: dict[str, str]) -> dict[str, Any] | None:
        """
        Consul Script Check

        SERVICE_CHECK_SCRIPT=curl --silent --fail example.com
        SERVICE_CHECK_SCRIPT=nc $SERVICE_IP $SERVICE_PORT | grep OK
        """
        # https://developer.hashicorp.com/consul/docs/discovery/checks#script-interval
        args = cls._value(params, "script")
        if args:
            args = args.replace("$SERVICE_IP", service.ip).replace("$SERVICE_PORT", str(service.port))
            interval = cls._value(params, "interval")
            ret = _build_check(args=shlex.split(args), interval=interval)
            return cls._post_process(ret, params)
        return None

    @classmethod
    def docker(cls, service: Service, params: dict[str, str]) -> dict[str, Any] | None:
        """
        Consul Docker Check

        SERVICE_CHECK_DOCKER=curl --silent --fail example.com
        """
        # https://developer.hashicorp.com/consul/docs/discovery/checks#docker-interval
        script = cls._value(params, "docker")
        if script:
            script = script.replace("$SERVICE_IP", service.ip).replace("$SERVICE_PORT", str(service.port))
            container_id = service.container_id[:12]
            shell = cls._value(params, "shell")
            interval, deregister = cls._common_values(params)
            ret = _build_check(
                docker_container_id=container_id,
                shell=shell,
                args=shlex.split(script),
                interval=interval,
                DeregisterCriticalServiceAfter=deregister,
            )
            return cls._post_process(ret, params)
        return None
