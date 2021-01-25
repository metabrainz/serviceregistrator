# serviceregistrator
#
# Copyright (C) 2021  MetaBrainz Foundation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from collections import defaultdict
import logging

from serviceregistrator.service import Service


log = logging.getLogger('serviceregistrator')


class ContainerInfo:
    def __init__(self, cid, name, ports, metadata, metadata_with_port, hostname, serviceip, tags):
        self.cid = cid
        self.name = name
        self.ports = ports
        self.metadata = metadata
        self.metadata_with_port = metadata_with_port
        self.hostname = hostname
        self.serviceip = serviceip
        self.service_prefix = None
        self.tags = tags

        self._services = None
        self._names_count = None

    def __str__(self):
        return f"<{self.name} ({self.cid[:12]})>"

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
            return self.service_prefix + ':' + name
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
            name = '{}-{}'.format(name, port.external)
            if port.protocol != 'tcp':
                name = '{}-{}'.format(name, port.protocol)
        return name

    def build_service_tags(self, port):
        tags = self.get_attr('tags', port.internal) or []
        if self.tags:
            tags.extend(self.tags)
        if port.protocol != 'tcp':
            tags.append(port.protocol)
        return list(set(tags))

    def build_service_attrs(self, port):
        return self.get_attr('attrs', port.internal) or {}

    def build_service_id(self, port):
        service_id = "{}:{}:{}".format(self.hostname, self.name, port.external)
        if port.protocol != 'tcp':
            service_id += ":" + port.protocol
        if self.service_prefix:
            service_id = "{}:{}".format(self.service_prefix, service_id)
        return service_id

    def build_service_ip(self, port):
        return self.get_attr('ip', port.internal) or self.serviceip

    @property
    def services(self):
        if self._services is not None:
            return self._services

        self._names_count = None

        services = list()
        for port in self.ports:
            service_name = self.build_service_name(port)
            if service_name is None:
                log.debug("Skipping port {}, no service name set".format(port))
                continue
            services.append(
                Service(
                    self.cid,
                    self.build_service_id(port),
                    service_name,
                    self.build_service_ip(port),
                    port.external,
                    tags=self.build_service_tags(port),
                    attrs=self.build_service_attrs(port)
                )
            )
        self._services = services
        return services

    def service_identifiers(self):
        return [service.id for service in self.services]
