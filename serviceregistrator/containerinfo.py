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

from collections import defaultdict
import hashlib
import ipaddress
import logging
from typing import Any

from serviceregistrator import ServiceIP
from serviceregistrator.service import Service


log = logging.getLogger("serviceregistrator")


class ContainerInfo:
    SERVICE_PREFIX_NAME_SEPARATOR = "-"
    SERVICE_ID_SEPARATOR = ":"

    def __init__(
        self,
        cid: str,
        name: str,
        ports: list[Any],
        metadata: Any,
        metadata_with_port: dict[int, Any],
        hostname: str,
        service_ips: list[ServiceIP],
        tags: list[str],
        ip_mode: str = "tag",
    ) -> None:
        self.cid = cid
        self.name = name
        self.metadata = metadata
        self.metadata_with_port = metadata_with_port
        self.hostname = hostname
        self.service_ips = service_ips
        self.ip_tag_map: dict[str, str] = {sip.ip: sip.tag for sip in service_ips if sip.tag}
        self.ip_mode = ip_mode
        self.service_prefix: str | None = None
        self.tags = [x for x in set(tags) if x]
        self.health: str | None = None

        # Expand wildcard bindings (0.0.0.0, ::, "") into one port per --ip
        self.ports: list[Any] = []
        for port in ports:
            if port.ip in {"0.0.0.0", "::", ""}:
                for sip in service_ips:
                    self.ports.append(port._replace(ip=sip.ip, ip_tag=sip.tag))
            else:
                self.ports.append(port)

        self._services: list[Service] | None = None
        self._names_count: dict[str | None, int] | None = None

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name} ({self.cid[:10]})>"

    def __repr__(self) -> str:
        return (
            "{t}('{s.cid}', '{s.name}', {s.ports}, {s.metadata}, {s.metadata_with_port}, "
            "'{s.hostname}', {s.service_ips}, {s.tags})"
        ).format(t=type(self).__name__, s=self)

    def __bool__(self) -> bool:
        return bool(self.metadata or self.metadata_with_port)

    def get_attr(self, key: str, port: int) -> Any:
        if port in self.metadata_with_port and key in self.metadata_with_port[port]:
            return self.metadata_with_port[port][key]
        elif key in self.metadata:
            return self.metadata[key]
        else:
            return None

    def get_name(self, port: Any) -> str | None:
        name = self.get_attr("name", port.internal)
        if name and self.service_prefix:
            return self.service_prefix + self.SERVICE_PREFIX_NAME_SEPARATOR + name
        return name

    def unique_ports_count(self) -> dict[str | None, int]:
        """Count services with same name, ignoring IP differences.

        Two ports that differ only by IP (same internal, external, protocol)
        are counted once — they represent the same service on multiple IPs.
        """
        seen: dict[str | None, set[tuple[int, str]]] = defaultdict(set)
        for port in self.ports:
            name = self.get_name(port)
            if name:
                seen[name].add((port.external, port.protocol))
        return {name: len(ports) for name, ports in seen.items()}

    def _get_port_ip_tag(self, port: Any, ip: str) -> str | None:
        """Get the IP tag for a port, preferring port.ip_tag over ip_tag_map."""
        if hasattr(port, "ip_tag"):
            return port.ip_tag
        return self.ip_tag_map.get(ip)

    def build_service_name(self, port: Any, ip: str | None = None) -> str | None:
        if self._names_count is None:
            self._names_count = self.unique_ports_count()
        name = self.get_name(port)
        count = self._names_count.get(name, 0)
        if count < 1:
            return None
        elif count > 1:
            name = f"{name}-{port.external}"
            if port.protocol != "tcp":
                name = f"{name}-{port.protocol}"
        if self.ip_mode == "prefix" and name:
            ip_tag = self._get_port_ip_tag(port, ip or "")
            if ip_tag:
                name = ip_tag + self.SERVICE_PREFIX_NAME_SEPARATOR + name
        return name

    def build_service_tags(self, port: Any, ip: str) -> list[str]:
        tags = list(self.get_attr("tags", port.internal) or [])
        if self.tags:
            tags.extend(self.tags)
        if port.protocol != "tcp":
            tags.append(port.protocol)
        ip_tag = self._get_port_ip_tag(port, ip)
        if ip_tag:
            tags.append(ip_tag)
        return [x for x in set(tags) if x]

    def build_service_attrs(self, port: Any) -> dict[str, str]:
        return self.get_attr("attrs", port.internal) or {}

    @staticmethod
    def _ip_hash(ip: str) -> str:
        """Return a short hash of an IP address for use in service IDs."""
        return hashlib.sha256(ip.encode()).hexdigest()[:8]

    def _has_multiple_untagged_ips(self, port: Any) -> bool:
        """Check if this (external port, protocol) has multiple untagged IPs."""
        count = sum(
            1
            for p in self.ports
            if p.external == port.external and p.protocol == port.protocol and not getattr(p, "ip_tag", None)
        )
        return count > 1

    SERVICE_ID_TAG_SEPARATOR = "@"

    def build_service_id(self, port: Any, ip: str) -> str:
        parts: list[str] = []
        if self.service_prefix:
            parts.append(self.service_prefix)
        parts.extend([self.hostname, self.name, str(port.external)])
        if port.protocol != "tcp":
            parts.append(str(port.protocol))
        base = self.SERVICE_ID_SEPARATOR.join(parts)
        tag = self._get_port_ip_tag(port, ip)
        if tag:
            return base + self.SERVICE_ID_TAG_SEPARATOR + tag
        elif self._has_multiple_untagged_ips(port):
            return base + self.SERVICE_ID_TAG_SEPARATOR + self._ip_hash(ip)
        return base

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IP address to prevent injection via SERVICE_IP."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def build_service_ip(self, port: Any) -> str:
        ip = self.get_attr("ip", port.internal)
        if ip is None:
            return port.ip
        elif self._validate_ip(ip):
            return ip
        else:
            log.warning(f"Invalid SERVICE_IP '{ip}' for {self}, using default")
            return self.service_ips[0][0]

    def build_service_alias(self, port: Any) -> str | None:
        attrs = self.build_service_attrs(port)
        return attrs.get("alias")

    @property
    def services(self) -> list[Service]:
        if self._services is None:
            self._names_count = None

            services: dict[str, Service] = dict()
            for port in self.ports:
                ip = self.build_service_ip(port)
                service_name = self.build_service_name(port, ip)
                if service_name is None:
                    log.info(f"Skipping port {port}, no service name set")
                    continue
                service_id = self.build_service_id(port, ip)
                if service_id in services:
                    log.warning(f"Service ID already exists: {service_id} ({self})")
                    continue
                service = Service(
                    self.cid,
                    service_id,
                    service_name,
                    ip,
                    port.external,
                    tags=self.build_service_tags(port, ip),
                    attrs=self.build_service_attrs(port),
                )
                services[service_id] = service

                # Create alias service if SERVICE_<port>_ALIAS is set
                alias_name = self.build_service_alias(port)
                if alias_name:
                    # Insert :alias before @tag so is_our_identifier can parse both
                    if self.SERVICE_ID_TAG_SEPARATOR in service_id:
                        base, tag_part = service_id.split(self.SERVICE_ID_TAG_SEPARATOR, 1)
                        alias_id = base + self.SERVICE_ID_SEPARATOR + "alias" + self.SERVICE_ID_TAG_SEPARATOR + tag_part
                    else:
                        alias_id = service_id + self.SERVICE_ID_SEPARATOR + "alias"
                    if alias_id in services:
                        log.warning(f"Alias ID already exists: {alias_id} ({self})")
                    else:
                        services[alias_id] = Service(
                            self.cid,
                            alias_id,
                            alias_name,
                            service.ip,
                            service.port,
                            tags=service.tags,
                            attrs={},
                            alias_of=service_name,
                        )
            self._services = list(services.values())
        return self._services

    def service_identifiers(self) -> list[str]:
        return [service.id for service in self.services]
