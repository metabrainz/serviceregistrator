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

from collections import namedtuple
from consul import ConsulException
from docker.models.containers import Container
import consul
import copy
import docker
import logging
import traceback
import re
import requests
import socket
from requests.exceptions import ConnectionError

from serviceregistrator import ContainerMetadata
from serviceregistrator.servicecheck import ServiceCheck
from serviceregistrator.service import Service
from serviceregistrator.containerinfo import ContainerInfo


log = logging.getLogger('serviceregistrator')


# Monkey Patch
# @see https://github.com/docker/docker-py/pull/1726

@property
def health(self):
    """
    The health of the app in the container.
    """
    if self.attrs['State'].get('Health') is not None:
        return self.attrs['State']['Health']['Status']
    else:
        return 'none'


Container.health = health

# fancier logging, Container.__repr__ is only returning short_id
# https://github.com/docker/docker-py/blob/a48a5a9647761406d66e8271f19fab7fa0c5f582/docker/models/resource.py#L20
# Add container name
Container.__repr__ = lambda self: f"<{self.__class__.__name__}: {self.name} ({self.short_id})>"


# Monkey patch default requests user agent
_USER_AGENT = None


def my_default_user_agent(name="python-requests"):
    global _USER_AGENT

    if _USER_AGENT is None:
        from importlib.metadata import version
        import platform
        _USER_AGENT = 'ServiceRegistrator/%s Python %s %s' % (
            version('serviceregistrator'),
            platform.python_version(),
            platform.system()
        )
    return _USER_AGENT


requests.utils.default_user_agent = my_default_user_agent


class ConsulConnectionError(Exception):
    def __init__(self, msg, *args, **kwargs):
        super().__init__(f'Consul connection error: {msg}', *args, **kwargs)


SERVICE_PORT_REGEX = re.compile(r'(?P<port>\d+)_(?P<key>.+)$')
SERVICE_KEY_REGEX = re.compile(r'SERVICE_(?P<key>.+)$')
SERVICE_KEYVAL_REGEX = re.compile(r'SERVICE_(?P<key>.+)=(?P<value>.*)$')

# https://www.consul.io/docs/discovery/services#service-and-tag-names-with-dns
# https://github.com/hashicorp/consul-template/blob/870905de57f085588c3b718b779d8550aefc5dcf/dependency/catalog_service.go#L18
# we only allow word characters, dashes & underscores in tags and service name
SERVICE_NAME_REGEX = re.compile(r'^[\w_-]+$')
SERVICE_TAG_REGEX = re.compile(r'^\s*(?P<tag>[\w_-]+)\s*$')

Ports = namedtuple('Ports', ('internal', 'external', 'protocol', 'ip'))


class ServiceRegistrator:
    unregister_actions = {
        'die',
        'health_status: unhealthy',
        'pause',
    }
    register_actions = {
        'health_status: healthy',
        'start'
    }
    handled_actions = unregister_actions | register_actions

    def __init__(self, context):
        self.context = context
        self.hostname = socket.gethostname()

        self._init_consul()
        self._init_docker()
        self.containers = self.context.containers

        log.info(f"Options: {context.options}")
        self.syncing = False

    def _init_docker(self):
        self.docker_client = docker.from_env()
        self.docker_api_client = docker.APIClient(base_url='unix://' + self.context.options['dockersock'])
        self.events = self.docker_client.events(decode=True)

        def close_events():
            log.debug("close events")
            self.events.close()
        self.context.register_on_exit('close_events', close_events)

    def _init_consul(self):
        host = self.context.options['consul_host']
        port = self.context.options['consul_port']

        try:
            self.consul_client = consul.Consul(host=host, port=port)
            peers = self.consul_client.status.peers()
            agent_self = self.consul_client.agent.self()
            self.consul_version = agent_self['Config']['Version']
            ServiceCheck.consul_version = tuple(map(int, self.consul_version.split('.')))
            log.info(f"Using Consul Agent {self.consul_version} at {host}:{port} (peers:{peers})")
        except (ConnectionError, ConsulException) as e:
            raise ConsulConnectionError(e)

    @staticmethod
    def fmtevent(action, etype, cid):
        return f"Event [{action}] type=[{etype}] cid=[{cid}]"

    def watch_events(self):
        debug = self.context.options['debug']
        for event in self.events:
            if self.context.kill_now:
                break
            if self.syncing:
                if debug:
                    log.debug("skip event, sync in progress...")
                continue
            action = event['Action']
            etype = event['Type']
            cid = event['Actor']['ID']

            # with only listen for container events
            if etype != 'container':
                if debug:
                    log.debug(self.fmtevent(action, etype, cid))
                continue

            if action not in self.handled_actions:
                if debug:
                    log.debug(self.fmtevent(action, etype, cid))
                continue

            log.info(self.fmtevent(action, etype, cid))

            container_info = self.parse_container_meta(cid)
            if not container_info:
                if debug:
                    log.debug(f"skipping {cid}")
                continue

            if action in self.register_actions:
                self.register_container(container_info)
            elif action in self.unregister_actions:
                self.unregister_container(container_info)

    def docker_get_container_by_id(self, cid):
        return self.docker_client.containers.get(cid)

    @staticmethod
    def extract_ports(container):
        """ Extract ports from container metadata"""

        ports = list()

        networkmode = container.attrs['HostConfig']['NetworkMode']
        if networkmode == 'host':
            # Extract configured host port mappings, relevant when using --net=host
            exposed_ports = container.attrs['Config']['ExposedPorts']
            if exposed_ports:
                for exposed_port in exposed_ports:
                    port, protocol = exposed_port.split('/')
                    ports.append(Ports(
                        internal=int(port),
                        external=int(port),
                        protocol=protocol,
                        ip="0.0.0.0"
                    ))
        elif networkmode in ('bridge', 'default'):
            # Extract runtime port mappings, relevant when using --net=bridge
            port_data = container.attrs['NetworkSettings']['Ports']
            # example: {'180/udp': [{'HostIp': '0.0.0.0', 'HostPort': '18082'}],
            #           '80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '28082'},
            #                      {'HostIp': '0.0.0.0', 'HostPort': '8082'}]}
            if port_data:
                for internal_port, external_ports in port_data.items():
                    port, protocol = internal_port.split('/')
                    for eport in external_ports:
                        ports.append(Ports(
                            internal=int(port),
                            external=int(eport['HostPort']),
                            protocol=protocol,
                            ip=eport['HostIp']
                        ))
        return ports

    @staticmethod
    def parse_env(env):
        kv = dict()
        for elem in env:
            m = SERVICE_KEYVAL_REGEX.match(elem)
            if m:
                key = m.group('key')
                value = m.group('value')
                kv[key] = value
        return kv

    @staticmethod
    def parse_labels(labels):
        kv = dict()
        for key, value in labels.items():
            m = SERVICE_KEY_REGEX.match(key)
            if m:
                key = m.group('key')
                kv[key] = value
        return kv

    @staticmethod
    def parse_tags_string(container, tags_string):
        valid_tags = dict()  # we use a dict to preserve tags order, but it emulates a set
        for tag in tags_string.split(','):
            if not tag:
                # skip empty strings. When `tags_string` is empty, `split(',')` will return
                # at least an empty string
                continue
            m = SERVICE_TAG_REGEX.match(tag)
            if m:
                valid_tags[m.group('tag')] = True
            else:
                log.warning(f"{container}: Invalid tag: '{tag}', ignoring")
        return ','.join(valid_tags)

    @classmethod
    def parse_service_meta(cls, container):
        # extract SERVICE_* from container env
        # There are 2 forms: one without port, one with port
        # SERVICE_80_NAME=thisname
        # SERVICE_NAME=thisname
        # when port is specified it will be used for matching internal port service
        # this is stored in two different dicts
        # those with ports are stored in metadata_with_port[<port>]

        # read from env vars
        kv_from_env = cls.parse_env(container.attrs['Config']['Env'])

        # read from container labels
        kv_from_labels = cls.parse_labels(container.labels)

        metadata = ContainerMetadata()
        metadata_with_port = dict()

        def validate_kv(key, value):
            if key == 'NAME':
                if not SERVICE_NAME_REGEX.match(value):
                    log.warning(f"{container}: Invalid service name: '{value}', ignoring")
                    return None
                else:
                    return value
            elif key == 'TAGS':
                return cls.parse_tags_string(container, value)
            else:
                return value

        def parse_service_key(key, value):
            log.debug(f"Parsing service key {key}: {value!r}")
            m = SERVICE_PORT_REGEX.match(key)
            if m:
                # matching SERVICE_<port>_
                key = m.group('key')
                port = int(m.group('port'))
                value = validate_kv(key, value)
                if value:
                    if port not in metadata_with_port:
                        metadata_with_port[port] = ContainerMetadata()
                    metadata_with_port[port][key] = value
            else:
                value = validate_kv(key, value)
                if value:
                    metadata[key] = value

        # values from env vars take precedence over the ones from labels
        for key, value in kv_from_labels.items():
            parse_service_key(key, value)
        for key, value in kv_from_env.items():
            parse_service_key(key, value)

        # default to metadata without port, and concatenate tag lists
        new_metadata_with_port = dict()
        for port, meta in metadata_with_port.items():
            new_metadata_with_port[port] = copy.deepcopy(metadata)
            new_metadata_with_port[port].update(meta)

        return metadata, new_metadata_with_port

    def parse_container_meta(self, cid):
        container = self.docker_get_container_by_id(cid)
        metadata, metadata_with_port = self.parse_service_meta(container)
        if not metadata and not metadata_with_port:
            # skip containers without SERVICE_*
            log.info(f"skip {container}: no SERVICE_*")
            return None
        ports = self.extract_ports(container)
        if not ports:
            # no exposed or published ports, skip
            log.info(f"skip {container}: no exposed ports")
            return None
        name = container.name
        tags = self.parse_tags_string(container, self.context.options['tags'])
        container_info = ContainerInfo(cid, name, ports, metadata, metadata_with_port,
                                       self.hostname, self.context.options['ip'], tags)
        if self.context.options['service_prefix']:
            container_info.service_prefix = self.context.options['service_prefix']
        health = container.health
        if health != 'none':
            container_info.health = health
        return container_info

    def docker_running_containers(self):
        return self.docker_client.containers.list(all=True, sparse=True, filters=dict(status='running'))

    def sync_with_containers(self):
        if self.syncing:
            # it can be called by signal
            return
        self.syncing = True
        log.info("Sync with containers")
        for container in self.docker_running_containers():
            cid = container.id
            container.reload()  # needed since we use sparse, and want health
            container_info = self.parse_container_meta(cid)
            if container_info:
                self.register_container(container_info)
            elif container_info is not None:
                log.debug(f"Skipping {container_info}")
            else:
                log.debug(f"Skipping {cid}")
        self.cleanup()
        self.syncing = False

    @staticmethod
    def make_check(service):
        checks = {
            'docker': ServiceCheck.docker,
            'http': ServiceCheck.http,
            'https': ServiceCheck.https,
            'script': ServiceCheck.script,
            'tcp': ServiceCheck.tcp,
            'ttl': ServiceCheck.ttl,
        }
        valid_checks = set(checks)
        check = None
        params = {}
        for key, value in service.attrs.items():
            if key.startswith('check_'):
                k = key[6:]
                params[k] = value
                if check is None and k in valid_checks:
                    check = k
        if check:
            try:
                ret = checks[check](service, params)
                if ret:
                    log.info(f"REGISTER CHECK {check} for service {service.id}: {ret}")
                return ret
            except Exception as e:
                log.error(f"error while setting check {check} for service {service.id}: {e}")
                log.error(traceback.format_exc())
        return None

    @staticmethod
    def service_meta(service):
        meta = {}
        for k, v in service.attrs.items():
            if k.startswith('check_'):
                # ignore SERVICE_CHECK_*
                continue
            if k == 'ip':
                # ignore SERVICE_IP
                continue
            meta[k] = v
        return meta

    def consul_register_service(self, service):
        log.info(f"REGISTER SERVICE {service}")
        log.debug(repr(service))
        try:
            self.consul_client.agent.service.register(
                name=service.name,
                service_id=service.id,
                address=service.ip,
                port=service.port,
                tags=service.tags,
                meta=self.service_meta(service),
                check=self.make_check(service)
            )
        except ConnectionError as e:
            raise ConsulConnectionError(e)
        except Exception as e:
            log.error(e)

    def consul_unregister_service(self, service):
        if isinstance(service, Service):
            log.info(f"UNREGISTER SERVICE {service}")
            service_id = service.id
            log.debug(repr(service))
        else:
            service_id = service
            log.info(f"UNREGISTER SERVICE with id {service_id}")
        try:
            self.consul_client.agent.service.deregister(service_id)
        except ConnectionError as e:
            raise ConsulConnectionError(e)
        except Exception as e:
            log.error(e)

    def register_services(self, container_info):
        for service in container_info.services:
            self.consul_register_service(service)

    def unregister_services(self, container_info):
        for service in container_info.services:
            self.consul_unregister_service(service)

    def register_container(self, container_info):
        if container_info.health is not None and container_info.health != 'healthy':
            log.info(f"SKIPPED CONTAINER (unhealthy): {container_info}")
            return
        log.info(f'REGISTER CONTAINER {container_info}')
        log.debug(repr(container_info))
        self.containers[container_info.cid] = container_info
        self.register_services(container_info)

    def unregister_container(self, container_info):
        if container_info.cid in self.containers:
            log.info(f'UNREGISTER CONTAINER {container_info}')
            log.debug(repr(container_info))
            try:
                self.unregister_services(container_info)
            except Exception as e:
                raise e
            else:
                del self.containers[container_info.cid]
                log.info(f'container {container_info} removed')
        else:
            log.debug(f"no registered container {container_info}")

    def is_our_identifier(self, serviceid, prefix=''):
        identifier = serviceid.split(':')
        length = len(identifier)
        if prefix:
            if identifier[0] != prefix:
                return False, "different prefix"
            else:
                identifier = identifier[1:]
                length -= 1
        if length < 3:
            return False, "length < 3"
        if length > 3:
            if identifier[-1] != 'udp':
                return False, "no udp"
            else:
                identifier = identifier[:-1]
                length -= 1
        if identifier[0] != self.hostname:
            return False, "different hostname"
        return True, None

    def containers_service_identifiers(self):
        services = []
        for cid, container_info in self.containers.items():
            services.extend(container_info.service_identifiers())
        return set(services)

    def consul_services(self):
        try:
            return self.consul_client.agent.services()
        except ConnectionError as e:
            raise ConsulConnectionError(e)
        except Exception as e:
            log.error(e)
            return {}

    def cleanup(self):
        log.info("services cleanup")
        registered_services = self.consul_services()
        our_services = self.containers_service_identifiers()
        prefix = self.context.options['service_prefix']
        for serviceid in registered_services:
            is_ours, comment = self.is_our_identifier(serviceid, prefix)
            if not is_ours:
                log.debug(f"cleanup: skipping {serviceid}, not ours ({comment})")
                continue
            if serviceid not in our_services:
                self.consul_unregister_service(serviceid)
