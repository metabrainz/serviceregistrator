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

import click
import docker
import logging
import traceback
from time import sleep

from serviceregistrator import Context
from serviceregistrator.registrator import ServiceRegistrator, ConsulConnectionError


log = logging.getLogger('serviceregistrator')


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
@click.option(
    '-i',
    '--ip',
    help="address to use for services without SERVICE_IP",
    required=True
)
@click.option(
    '-t',
    '--tags',
    help='comma-separated list of tags to append to all registered services',
    default=''
)
@click.option(
    '-h',
    '--consul-host',
    help='consul agent host',
    default='127.0.0.1',
    show_default=True
)
@click.option(
    '-p',
    '--consul-port',
    help='consul agent port',
    default=8500,
    type=click.INT,
    show_default=True
)
@click.option(
    '-k',
    '--dockersock',
    help='path to docker socket',
    default='unix://var/run/docker.sock',
    show_default=True
)
@click.option(
    '-d',
    '--delay',
    help="delay in seconds between docker connection attempts",
    default=1,
    show_default=True
)
@click.option(
    '-s',
    '--resync',
    help='delay between each forced services resync',
    default=0,
    type=click.INT,
    show_default="disabled"
)
@click.option(
    '-f',
    '--logfile',
    help="log file path",
    default=None
)
@click.option(
    '-l',
    '--loglevel',
    help="log level",
    default="INFO",
    show_default=True,
    type=click.Choice(POSSIBLE_LEVELS, case_sensitive=False),
    callback=loglevelfmt
)
@click.option(
    '-G',
    '--debug',
    help='output extra debug info',
    is_flag=True
)
@click.option(
    '-R',
    '--debug-requests',
    help='log requests too (debug)',
    default=False,
    is_flag=True
)
@click.option(
    '-P',
    '--service-prefix',
    help='string to prepend to all service names and IDs (testing purpose)',
    default=None
)
def main(**options):
    """Register docker containers as consul services"""
    context = Context(options)
    delay = context.options['delay']
    consul_connected = False

    if context.options['debug_requests']:
        import http.client
        http.client.HTTPConnection.debuglevel = 1

    while not context.kill_now:
        try:
            context.serviceregistrator = ServiceRegistrator(context)
            consul_connected = True
            context.serviceregistrator.sync_with_containers()
            context.serviceregistrator.watch_events()
        except ConsulConnectionError as e:
            if consul_connected:
                log.error(e)
            consul_connected = False
        except docker.errors.DockerException as e:
            log.error(e)
        except Exception as e:
            log.error(e)
            log.error(traceback.format_exc())
        finally:
            if not context.kill_now:
                log.debug("sleeping {} second(s)...".format(delay))
                for _unused in range(0, delay):
                    if not context.kill_now:
                        sleep(1)


if __name__ == "__main__":
    main()
