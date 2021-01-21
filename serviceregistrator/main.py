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

import signal
from collections import namedtuple
from docker.models.containers import Container
import click
import copy
import docker
import logging
import traceback
import re
import sys
from time import sleep

from serviceregistrator import ContainerMetadata


log = logging.getLogger(__name__)


def configure_logging(options):
    console_handler = logging.StreamHandler(sys.stderr)
    handlers = [console_handler]
    if options['logfile']:
        try:
            filehandler = logging.FileHandler(filename=options['logfile'])
            handlers.append(filehandler)
        except Exception:
            pass

    logging.basicConfig(
        level=logging.ERROR,
        format='[%(asctime)s] {%(module)s:%(lineno)d} %(levelname)s - %(message)s',
        handlers=handlers
    )
    try:
        log.setLevel(options['loglevel'])
    except ValueError as e:
        log.error(e)


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


class Service:

    def __init__(self, id_, name, ip, port, tags=None, attrs=None):
        #  https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/docs/user/services.md#service-object
        self.id = id_      # string               // unique service instance ID
        self.name = name   # string               // service name
        self.ip = ip       # string               // IP address service is located at
        self.port = port   # int                  // port service is listening on
        # []string             // extra tags to classify service
        self.tags = tags if not None else []
        #  map[string]string    // extra attribute metadata
        self.attrs = attrs if not None else dict()

    def __str__(self):
        return '==== Service id: {} ====\nname: {}\nip: {}\nport: {}\ntags: {}\nattrs: {}\n'.format(
            self.id, self.name, self.ip,
            self.port, self.tags, self.attrs)

    def __repr__(self):
        return f"{type(self).__name__}('{self.id}', '{self.name}', '{self.ip}', {self.port}, tags={self.tags}, attrs={self.attrs}')"


class ContainerInfo:
    def __init__(self, cid, name, ports, metadata, metadata_with_port, hostname, serviceip):
        self.cid = cid
        self.name = name
        self.ports = ports
        self.metadata = metadata
        self.metadata_with_port = metadata_with_port
        self.hostname = hostname
        self.serviceip = serviceip

    def __str__(self):
        return '==== name:{} ====\ncid: {}\nports: {}\nmetadata: {}\nmetadata_with_port: {}\nhostname: {}\nservices: \n{}\n'.format(
            self.name, self.cid, self.ports,
            self.metadata, self.metadata_with_port,
            self.hostname, self.services)

    def __bool__(self):
        return bool(self.metadata or self.metadata_with_port)

    def register(self, containers):
        log.info('register {}'.format(self.name))
        if self.cid in containers:
            log.info('updating {} containers'.format(self.name))
        else:
            log.info('adding {} to containers'.format(self.name))
        containers[self.cid] = self

    def unregister(self, containers):
        log.info('register {}'.format(self.name))
        try:
            del containers[self.cid]
            log.info('removing {} from containers'.format(self.name))
        except KeyError:
            pass

    @property
    def services(self):
        def getattr(key, port):
            if port in self.metadata_with_port and key in self.metadata_with_port[port]:
                return self.metadata_with_port[port][key]
            elif key in self.metadata:
                return self.metadata[key]
            else:
                return None
        services = list()
        for port in self.ports:
            service_id = "{}:{}:{}".format(self.hostname, self.name, port.external)
            service_port = port.external
            service_name = getattr('name', port.internal)
            if not service_name:
                log.debug("Skipping port {}, no service name set".format(port))
                continue
            service_tags = getattr('tags', port.internal) or []
            service_attrs = getattr('attrs', port.internal) or {}
            service_id = "{}:{}:{}".format(self.hostname, self.name, port.external)
            if port.protocol != 'tcp':
                service_id += ":udp"
                service_tags.append('udp')
            service_ip = getattr('ip', port.internal) or self.serviceip
            service = Service(service_id, service_name, service_ip,
                              port.external, tags=service_tags, attrs=service_attrs)
            services.append(service)
        return services


SERVICE_PORT_REGEX = re.compile(r'(?P<port>\d+)_(?P<key>.+)$')
SERVICE_KEY_REGEX = re.compile(r'SERVICE_(?P<key>.+)$')
SERVICE_KEYVAL_REGEX = re.compile(r'SERVICE_(?P<key>.+)=(?P<value>.*)$')

Ports = namedtuple('Ports', ('internal', 'external', 'protocol', 'ip'))


class ServiceRegistrator:

    def __init__(self, context):
        self.context = context
        log.info("Using IP: {}".format(context.options['ip']))
        log.info("Using docker socket: {}".format(context.options['dockersock']))
        self._init_docker()
        self._init_consul()
        self.containers = self.context.containers

    def _init_docker(self):
        self.docker_client = docker.from_env()
        self.docker_api_client = docker.APIClient(base_url=self.context.options['dockersock'])
        self.events = self.docker_client.events(decode=True)

        def close_events():
            log.debug("close events")
            self.events.close()
        self.context.register_on_exit(close_events)

    def _init_consul(self):
        pass

    def listen_events(self):
        yield from self.events

    def dump_events(self):
        # TODO: handle exceptions
        for event in self.listen_events():
            if self.context.kill_now:
                break
            action = event['Action']
            etype = event['Type']

            # with only listen for container events
            if etype != 'container':
                continue

            # Ignore health checks
            if action.startswith("exec_"):
                continue

            # Ignore image destroy (ecs does this regularly)
            if action == 'destroy':
                continue

            cid = event['Actor']['ID']
            log.info("Event [{}] type=[{}] cid=[{}]".format(
                action, etype, cid))

            container_info = self.parse_container_meta(cid)
            if not container_info:
                continue
            log.info(container_info)

            if cid in self.containers and action in ('pause', 'health_status: unhealthy', 'stop', 'die', 'kill', 'oom'):
                container_info.unregister(self.containers)
                continue

            if action in ('health_status: healthy', 'start'):
                container_info.register(self.containers)
                continue

    def docker_get_container_by_id(self, cid):
        return self.docker_client.containers.get(cid)

    @staticmethod
    def extract_ports(container):
        """ Extract ports from container metadata"""

        defaultip = ""
        networkmode = container.attrs['HostConfig']['NetworkMode']
        if networkmode not in ('bridge', 'default', 'host'):
            # not yet used
            defaultip = container.attrs['NetworkSettings']['Networks'][networkmode]['IPAddress']
        if not defaultip:
            defaultip = "0.0.0.0"

        ports = list()

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
                        ip=defaultip
                    ))
        else:
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

        def parse_service_key(key, value):
            m = SERVICE_PORT_REGEX.match(key)
            if m:
                # matching SERVICE_<port>_
                key = m.group('key')
                port = int(m.group('port'))
                if port not in metadata_with_port:
                    metadata_with_port[port] = ContainerMetadata()
                metadata_with_port[port][key] = value
            else:
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
            log.debug("skip container {} without SERVICE_*".format(cid))
            return None
        ports = self.extract_ports(container)
        if not ports:
            # no exposed or published ports, skip
            log.debug("skip container {} without exposed ports".format(cid))
            return None
        name = container.name
        hostname = container.attrs['Config']['Hostname']
        return ContainerInfo(cid, name, ports, metadata, metadata_with_port, hostname, self.context.options['ip'])

    def docker_running_containers(self):
        return self.docker_client.containers.list(all=True, sparse=True, filters=dict(status='running'))

    def list_containers(self):
        for container in self.docker_running_containers():
            cid = container.id
            if cid not in self.containers:
                container.reload()  # needed since we use sparse, and want health
                container_info = self.parse_container_meta(cid)
                if container_info:
                    container_info.register(self.containers)
                    log.info(container_info)
                elif container_info is not None:
                    log.debug("Skipping {}".format(container_info))
                else:
                    log.debug("Skipping {}".format(cid))
            else:
                log.debug("{} already in containers".format(cid))


class Context:
    kill_now = False
    on_exit = list()
    signals = {
        signal.SIGINT: 'SIGINT',
        signal.SIGTERM: 'SIGTERM'
    }

    def __init__(self, options):
        self.options = options
        configure_logging(options)
        self.containers = {}
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        log.info("Received {} signal".format(self.signals[signum]))
        self.kill_now = True
        for func in self.on_exit:
            func()
        log.info("Exiting gracefully...")

    def register_on_exit(self, func):
        self.on_exit.append(func)


def loglevelfmt(ctx, param, value):
    if value is not None:
        return value.upper()


POSSIBLE_LEVELS = (
    'CRITICAL',
    'ERROR',
    'WARNING',
    'INFO',
    'DEBUG',
)


@click.command()
@click.option('-lf', '--logfile', default=None, help="log file path")
@click.option('-ll', '--loglevel', default="DEBUG", help="log level",
              type=click.Choice(POSSIBLE_LEVELS, case_sensitive=False),
              callback=loglevelfmt)
@click.option('-ip', '--ip', required=True, help="ip to use for services")
@click.option('-dy', '--delay', default=1, help="sleep delay between attempts to connect to docker")
@click.option('-ds', '--dockersock', default='unix://var/run/docker.sock', help='path to docker socket')
def main(**options):
    """Register docker services into consul"""
    context = Context(options)

    while not context.kill_now:
        try:
            log.info("Starting...")
            serviceregistrator = ServiceRegistrator(context)
            serviceregistrator.list_containers()
            serviceregistrator.dump_events()
        except docker.errors.DockerException as e:
            log.error(e)
        except Exception:
            log.error(traceback.format_exc())
            break
        finally:
            if not context.kill_now:
                delay = context.options['delay']
                log.debug("sleeping {} second(s)...".format(delay))
                sleep(delay)


if __name__ == "__main__":
    main()
