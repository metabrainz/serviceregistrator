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
import logging

from serviceregistrator.service import Service


log = logging.getLogger('serviceregistrator')


class ContainerInfo:

    SERVICE_PREFIX_NAME_SEPARATOR = '-'
    SERVICE_ID_SEPARATOR = ':'

    def __init__(self, cid, name, ports, metadata, metadata_with_port, hostname, serviceip, tags):
        self.cid = cid
        self.name = name
        self.ports = ports
        self.metadata = metadata
        self.metadata_with_port = metadata_with_port
        self.hostname = hostname
        self.serviceip = serviceip
        self.service_prefix = None
        self.tags = [x for x in set(tags) if x]
        self.health = None

        self._services = None
        self._names_count = None

    def __str__(self):
        return f"<{self.__class__.__name__}: {self.name} ({self.cid[:10]})>"

    def __repr__(self):
        return (
            "{t}('{s.cid}', '{s.name}', {s.ports}, {s.metadata}, {s.metadata_with_port}, "
            "'{s.hostname}', '{s.serviceip}', {s.tags})").format(t=type(self).__name__, s=self)

    def __bool__(self):
        return bool(self.metadata or self.metadata_with_port)

    def get_attr(self, key, port):
        if port in self.metadata_with_port and key in self.metadata_with_port[port]:
            return self.metadata_with_port[port][key]
        elif key in self.metadata:
            return self.metadata[key]
        else:
            return None

    def get_name(self, port):
        name = self.get_attr('name', port.internal)
        if name and self.service_prefix:
            return self.service_prefix + self.SERVICE_PREFIX_NAME_SEPARATOR + name
        return name

    def names_count(self):
        """Count services with same name or no name"""
        names_count = defaultdict(lambda: 0)
        for port in self.ports:
            name = self.get_name(port)
            if name:
                names_count[name] += 1
        return names_count

    def build_service_name(self, port):
        if self._names_count is None:
            self._names_count = self.names_count()
        name = self.get_name(port)
        count = self._names_count[name]
        if count < 1:
            return None
        elif count > 1:
            name = f'{name}-{port.external}'
            if port.protocol != 'tcp':
                name = f'{name}-{port.protocol}'
        return name

    def build_service_tags(self, port):
        tags = self.get_attr('tags', port.internal) or []
        if self.tags:
            tags.extend(self.tags)
        if port.protocol != 'tcp':
            tags.append(port.protocol)
        return [x for x in set(tags) if x]

    def build_service_attrs(self, port):
        return self.get_attr('attrs', port.internal) or {}

    def build_service_id(self, port):
        parts = []
        if self.service_prefix:
            parts.append(self.service_prefix)
        parts.extend([self.hostname, self.name, str(port.external)])
        if port.protocol != 'tcp':
            parts.append(str(port.protocol))
        return self.SERVICE_ID_SEPARATOR.join(parts)

    def build_service_ip(self, port):
        ip = self.get_attr('ip', port.internal)
        if ip is None:
            if port.ip not in {'0.0.0.0', '::', ''}:
                return port.ip
            else:
                return self.serviceip
        else:
            return ip

    @property
    def services(self):
        if self._services is None:
            self._names_count = None

            services = dict()
            for port in self.ports:
                service_name = self.build_service_name(port)
                if service_name is None:
                    log.info(f"Skipping port {port}, no service name set")
                    continue
                if service_name in services:
                    # this shouldn't happen, but emit a warning and skip if it does
                    log.warning(f"Service name already exists: {service_name} ({self})")
                    continue
                services[service_name] = Service(
                    self.cid,
                    self.build_service_id(port),
                    service_name,
                    self.build_service_ip(port),
                    port.external,
                    tags=self.build_service_tags(port),
                    attrs=self.build_service_attrs(port)
                )
            self._services = list(services.values())
        return self._services

    def service_identifiers(self):
        return [service.id for service in self.services]
