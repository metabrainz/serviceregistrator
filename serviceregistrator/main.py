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
import docker
import logging
import traceback
import re
import sys


log = logging.getLogger(__name__)


def configure_logging(options):
    console_handler = logging.StreamHandler(sys.stderr)
    handlers = [console_handler]
    if options['logfile']:
        try:
            filehandler = logging.FileHandler(filename=options['logfile'])
            handlers.append(filehandler)
        except Exception as e:
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
        ## https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/docs/user/services.md#service-object
        self.id = id_      # string               // unique service instance ID
        self.name = name   # string               // service name
        self.ip = ip       # string               // IP address service is located at
        self.port = port   # int                  // port service is listening on
        self.tags = tags if not None else []        # []string             // extra tags to classify service
        self.attrs = attrs if not None else dict()  # map[string]string    // extra attribute metadata


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


class ServiceRegistrator:

    def __init__(self, config):
        self.config = config
        self.docker_client = docker.from_env()
        self.docker_api_client = docker.APIClient(
            base_url='unix://var/run/docker.sock')
        self.containers = {}

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

            # print(event)

            # Ignore health checks
            if action.startswith("exec_"):
                continue

            # Ignore image destroy (ecs does this regularly)
            if action == 'destroy':
                continue

            # print(event)

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


    def parse_container_meta(self, cid):
        container = self.docker_client.containers.get(cid)
        name = container.name
        hostname = container.attrs['Config']['Hostname']

        # extract ports
        port_data = container.attrs['NetworkSettings']['Ports']
        # example: {'180/udp': [{'HostIp': '0.0.0.0', 'HostPort': '18082'}], '80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '28082'}, {'HostIp': '0.0.0.0', 'HostPort': '8082'}]}
        ports = []
        #print(port_data)
        if port_data:
            ports = []
            Ports = namedtuple('Ports', ('internal', 'external', 'protocol'))
            for internal_port, external_ports in port_data.items():
                port, protocol = internal_port.split('/')
                for eport in external_ports:
                    ports.append(Ports(internal=port, external=int(eport['HostPort']), protocol=protocol))

            # example: [Ports(internal='180', external=18082, protocol='udp'), Ports(internal='80', external=28082, protocol='tcp'), Ports(internal='80', external=8082, protocol='tcp')]

        #print("===== ports =====")
        #print(ports)

        def parse_service_meta(meta):
            # extract SERVICE_* from container env
            # There are 2 forms: one without port, one with port
            # SERVICE_80_NAME=thisname
            # SERVICE_NAME=thisname
            # when port is specified it will be used for matching internal port service
            # this is stored in two different dicts
            # those with ports are stored in metadata_with_port[<port>]

            def transform(value, key):
                if key in ('tags', ):
                    return value.split(',')
                else:
                    return value

            # print(container.attrs['Config']['Env'])
            service_port_regex = re.compile(r'(?P<port>\d+)_(?P<key>.+)$')
            service_regex = re.compile(r'SERVICE_(?P<key>.+)=(?P<value>.+)$')
            metadata = dict()
            metadata_with_port = dict()
            for elem in container.attrs['Config']['Env']:
                #print(elem)
                m = service_regex.match(elem)
                if m:
                    #print(m.groupdict())
                    key = m.group('key')
                    value = m.group('value')
                    m = service_port_regex.match(key)
                    if m:
                        # matching SERVICE_<port>_
                        #print(m.groupdict())
                        key = m.group('key').lower()
                        port = int(m.group('port'))
                        if port not in metadata_with_port:
                            metadata_with_port[port] = dict()
                        metadata_with_port[port][key] = transform(value, key)
                    else:
                        key = key.lower()
                        metadata[key] = transform(value, key)
            return metadata, metadata_with_port

        #print("===== env =======")
        #print(container.attrs['Config']['Env'])
        metadata, metadata_with_port = parse_service_meta(container.attrs['Config']['Env'])
        return ContainerInfo(cid, name, ports, metadata, metadata_with_port, hostname)

    def list_containers(self):
        # print(self.docker_client.containers)
        for container in self.docker_client.containers.list(all=True, sparse=True):
            # print(container.attrs)
            attrs = container.attrs
            cid = container.id
            state = container.status
            if state == 'running' and cid not in self.containers:
                container.reload()  # needed since we use sparse, and want health
                container_info = self.parse_container_meta(cid)
                if container_info.can_register():
                    container_info.register(self.containers)
                    log.info(container_info)
                # print(container.attrs)
                # print(container.health)

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
