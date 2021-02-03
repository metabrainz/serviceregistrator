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
@click.option('-lf', '--logfile', default=None, help="log file path")
@click.option('-ll', '--loglevel', default="INFO", help="log level",
              type=click.Choice(POSSIBLE_LEVELS, case_sensitive=False),
              callback=loglevelfmt)
@click.option('-ip', '--ip', required=True, help="ip to use for services")
@click.option('-dy', '--delay', default=1, help="sleep delay between attempts to connect to docker")
@click.option('-ds', '--dockersock', default='unix://var/run/docker.sock', help='path to docker socket')
@click.option('-dg', '--debug', is_flag=True, help='Output extra debug info')
@click.option('-sp', '--service-prefix', default=None, help='service ID/name prefix (for testing purposes)')
@click.option('-ch', '--consul-host', default='127.0.0.1', help='consul agent host')
@click.option('-cp', '--consul-port', default=8500, type=click.INT, help='consul agent port')
@click.option('-t', '--tags', default='', help='comma-separated list of tags to append to all registered services')
@click.option('-dr', '--debug-requests', default=False, is_flag=True, help='log requests')
def main(**options):
    """Register docker services into consul"""
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
                sleep(delay)


if __name__ == "__main__":
    main()
