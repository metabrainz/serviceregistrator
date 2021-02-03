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

from collections import UserDict
import logging
import signal
import sys


log = logging.getLogger('serviceregistrator')


class ContainerMetadata(UserDict):
    def __setitem__(self, key, value):
        # all keys are lowered
        key = key.lower()
        if key in ('tags', ):
            # handle lists merging
            if value is None:
                value = []
            elif not isinstance(value, list):
                value = list(set(value.split(',')))
            if key in self:
                # uniqify
                super().__setitem__(key, list(set(self[key] + value)))
            else:
                super().__setitem__(key, value)

        elif key in ('name', 'id', 'ip'):
            # those keys are added as is
            super().__setitem__(key, value)
        elif key in ('attrs', ):
            # handle dict merging
            if key in self:
                self[key].update(value)
            else:
                super().__setitem__(key, value)
        else:
            # all other keys are added as attributes
            if 'attrs' not in self:
                super().__setitem__('attrs', dict())
            self['attrs'][key] = value

    def __repr__(self):
        return f"{type(self).__name__}({self.data})"


class Context:
    kill_now = False
    on_exit = dict()
    _sig2name = None
    serviceregistrator = None

    def __init__(self, options):
        self.options = options
        self.configure_logging(options)
        self.containers = {}

        # exit signals
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        # following signals may be used later
        signal.signal(signal.SIGUSR1, self.ignore_signal)
        signal.signal(signal.SIGUSR2, self.ignore_signal)

        # those signals force a resynchronisation
        signal.signal(signal.SIGHUP, self.sync_with_containers)
        signal.signal(signal.SIGALRM, self.sync_with_containers)
        resync = float(self.options['resync'])
        if resync > 0.0:
            log.info("Resync every {} seconds".format(resync))
            signal.setitimer(signal.ITIMER_REAL, resync, resync)

    def _log_signal(self, signum):
        if self._sig2name is None:
            # extract signal names from signal module
            # signal.Signals is an enum
            self._sig2name = dict([(s.value, s.name) for s in signal.Signals])

        name = self._sig2name.get(signum, signum)
        log.info("Received {} signal".format(name))

    def ignore_signal(self, signum, frame):
        self._log_signal(signum)

    def exit_gracefully(self, signum, frame):
        self._log_signal(signum)
        self.kill_now = True
        for func in self.on_exit.values():
            func()
        log.info("Exiting gracefully...")

    def register_on_exit(self, name, func):
        self.on_exit[name] = func

    def sync_with_containers(self, signum, frame):
        self._log_signal(signum)
        if self.serviceregistrator:
            self.serviceregistrator.sync_with_containers()

    def configure_logging(self, options):
        console_handler = logging.StreamHandler(sys.stderr)
        handlers = [console_handler]
        logfile = self.options['logfile']
        if logfile:
            try:
                filehandler = logging.FileHandler(filename=logfile)
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
