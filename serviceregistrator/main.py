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
        level=logging.DEBUG,
        format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
        handlers=handlers
    )
    try:
        log.setLevel(options['loglevel'])
    except ValueError as e:
        log.error(e)


@click.command()
@click.option('-c', '--config', default=None)
@click.option('-lf', '--logfile', default=None)
@click.option('-ll', '--loglevel', default="INFO")
def main(config, **options):
    configure_logging(options)

    try:
        log.info("Starting...")
        log.debug("debug")

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
