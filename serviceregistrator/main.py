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

from collections import namedtuple
from docker.models.containers import Container
import click
import copy
import docker
import logging
import traceback
import re
import sys

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


class ContainerInfo:
    def __init__(self, cid, name, ports, metadata, metadata_with_port, hostname):
        self.cid = cid
        self.name = name
        self.ports = ports
        self.metadata = metadata
        self.metadata_with_port = metadata_with_port
        self.hostname = hostname

    def __str__(self):
        return '==== name:{} ====\ncid: {}\nports: {}\nmetadata: {}\nmetadata_with_port: {}\nhostname: {}\n'.format(
            self.name, self.cid, self.ports,
            self.metadata, self.metadata_with_port,
            self.hostname)

    def can_register(self):
        return self.metadata or self.metadata_with_port

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


SERVICE_PORT_REGEX = re.compile(r'(?P<port>\d+)_(?P<key>.+)$')
SERVICE_KEY_REGEX = re.compile(r'SERVICE_(?P<key>.+)$')
SERVICE_KEYVAL_REGEX = re.compile(r'SERVICE_(?P<key>.+)=(?P<value>.*)$')


class ServiceRegistrator:
    _docker_sock = 'unix://var/run/docker.sock'

    def __init__(self, config):
        self.config = config
        self._init_docker()
        self._init_consul()
        self.containers = {}

    def _init_docker(self):
        self.docker_client = docker.from_env()
        self.docker_api_client = docker.APIClient(base_url=self._docker_sock)

    def _init_consul(self):
        pass

    def listen_events(self):
        yield from self.docker_client.events(decode=True)

    def dump_events(self):
        # TODO: handle exceptions
        for event in self.listen_events():
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
            if not container_info.can_register():
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
        # extract ports
        port_data = container.attrs['NetworkSettings']['Ports']
        # example: {'180/udp': [{'HostIp': '0.0.0.0', 'HostPort': '18082'}],
        #           '80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '28082'},
        #                      {'HostIp': '0.0.0.0', 'HostPort': '8082'}]}
        ports = []
        if port_data:
            ports = []
            Ports = namedtuple('Ports', ('internal', 'external', 'protocol'))
            for internal_port, external_ports in port_data.items():
                port, protocol = internal_port.split('/')
                for eport in external_ports:
                    ports.append(
                        Ports(
                            internal=port,
                            external=int(eport['HostPort']),
                            protocol=protocol
                        )
                    )

            # example: [Ports(internal='180', external=18082, protocol='udp'),
            #           Ports(internal='80', external=28082, protocol='tcp'),
            #           Ports(internal='80', external=8082, protocol='tcp')]
        return ports

    @staticmethod
    def parse_service_meta(container):
        # extract SERVICE_* from container env
        # There are 2 forms: one without port, one with port
        # SERVICE_80_NAME=thisname
        # SERVICE_NAME=thisname
        # when port is specified it will be used for matching internal port service
        # this is stored in two different dicts
        # those with ports are stored in metadata_with_port[<port>]

        # read from env vars
        kv_from_env = dict()
        for elem in container.attrs['Config']['Env']:
            m = SERVICE_KEYVAL_REGEX.match(elem)
            if m:
                # print(m.groupdict())
                key = m.group('key')
                value = m.group('value')
                kv_from_env[key] = value

        # read from container labels
        kv_from_labels = dict()
        for key, value in container.labels.items():
            m = SERVICE_KEY_REGEX.match(key)
            if m:
                key = m.group('key')
                kv_from_labels[key] = value

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
        name = container.name
        hostname = container.attrs['Config']['Hostname']

        metadata, metadata_with_port = self.parse_service_meta(container)
        ports = self.extract_ports(container)
        return ContainerInfo(cid, name, ports, metadata, metadata_with_port, hostname)

    def docker_running_containers(self):
        return self.docker_client.containers.list(all=True, sparse=True, filters=dict(status='running'))

    def list_containers(self):
        for container in self.docker_running_containers():
            cid = container.id
            if cid not in self.containers:
                container.reload()  # needed since we use sparse, and want health
                container_info = self.parse_container_meta(cid)
                if container_info.can_register():
                    container_info.register(self.containers)
                    log.info(container_info)
                # TODO check if service is registered


class Config:

    def __init__(self, options):
        self.options = options
        configure_logging(options)


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
@click.option('-ip', '--ip', default='127.0.0.1', help="ip to use for services")
def main(**options):
    """Register docker services into consul"""
    config = Config(options)

    try:
        log.info("Starting...")
        log.debug("debug")
        serviceregistrator = ServiceRegistrator(config)
        serviceregistrator.list_containers()
        serviceregistrator.dump_events()
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt... exiting gracefully")
    except SystemExit:
        log.info("SystemExit... exiting gracefully")
    except Exception:
        log.error(traceback.format_exc())
    finally:
        log.debug("finally...")


if __name__ == "__main__":
    main()
