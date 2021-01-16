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

from docker.models.containers import Container
import click
import docker
import logging
import traceback
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

            print(event)

            cid = event['Actor']['ID']
            if cid in self.containers:
                log.info("Known container: {}".format(cid))

            log.info("Event [{}] type=[{}] cid=[{}]".format(
                action, etype, cid))

            if action in ('pause', 'health_status: unhealthy', 'stop', 'die', 'kill', 'oom'):
                log.debug('deregister')
                # continue

            if action in ('health_status: healthy', 'start'):
                log.debug('register')
                # continue

            # TODO: handle event
            print(event)
            container = self.docker_client.containers.get(cid)
            print(container.attrs['Config']['Env'])

            def parse_meta(meta):
                metadata = dict()
                prefix = 'SERVICE_'
                for item in meta:
                    if item.startswith(prefix):
                        k, v = item.split('=', 2)
                        key = k[len(prefix):].lower()
                        metadata[k] = v
                return metadata

            print(parse_meta(container.attrs['Config']['Env']))

            #print(container.attrs['NetworkSettings']['Ports'])
            port_data = container.attrs['NetworkSettings']['Ports']
            if port_data:
                ports = [(int(k.split("/")[0]), int(p[0]['HostPort'])) for k,p in port_data.items() if p]
            else:
                ports = None
            print(ports)

    def list_containers(self):
        # print(self.docker_client.containers)
        for container in self.docker_client.containers.list(all=True, sparse=True):
            # print(container.attrs)
            attrs = container.attrs
            cid = container.id
            state = container.status
            if state == 'running' and cid not in self.containers:
                container.reload()  # needed since we use sparse, and want health
                self.containers[cid] = container
                # print(container.attrs)
                # print(container.health)


@click.command()
@click.option('-c', '--config', default=None)
@click.option('-lf', '--logfile', default=None)
@click.option('-ll', '--loglevel', default="INFO")
def main(config, **options):
    configure_logging(options)

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
