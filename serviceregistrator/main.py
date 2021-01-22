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
from collections import defaultdict, namedtuple
from consul import ConsulException, Check
from docker.models.containers import Container
import click
import consul
import copy
import docker
import json
import logging
import traceback
import re
import socket
import sys
from requests.exceptions import ConnectionError
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

    def __init__(self, container_id, id_, name, ip, port, tags=None, attrs=None):
        #  https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/docs/user/services.md#service-object
        self.id = id_      # string               // unique service instance ID
        self.name = name   # string               // service name
        self.ip = ip       # string               // IP address service is located at
        self.port = port   # int                  // port service is listening on
        # []string             // extra tags to classify service
        self.tags = tags if not None else []
        #  map[string]string    // extra attribute metadata
        self.attrs = attrs if not None else dict()
        self.container_id = container_id

    def __str__(self):
        return '==== Service id: {} ====\nname: {}\nip: {}\nport: {}\ntags: {}\nattrs: {}\n'.format(
            self.id, self.name, self.ip,
            self.port, self.tags, self.attrs)

    def __repr__(self):
        return f"{type(self).__name__}('{self.container_id}', {self.id}', '{self.name}', '{self.ip}', {self.port}, tags={self.tags}, attrs={self.attrs}')"


class ContainerInfo:
    def __init__(self, cid, name, ports, metadata, metadata_with_port, hostname, serviceip):
        self.cid = cid
        self.name = name
        self.ports = ports
        self.metadata = metadata
        self.metadata_with_port = metadata_with_port
        self.hostname = hostname
        self.serviceip = serviceip
        self.serviceid_prefix = None
        self._services = None

    def __str__(self):
        return '==== name:{} ====\ncid: {}\nports: {}\nmetadata: {}\nmetadata_with_port: {}\nhostname: {}\nservices: \n{}\n'.format(
            self.name, self.cid, self.ports,
            self.metadata, self.metadata_with_port,
            self.hostname, self.services)

    def __bool__(self):
        return bool(self.metadata or self.metadata_with_port)

    @property
    def services(self):
        if self._services is not None:
            return self._services

        def getattr(key, port):
            if port in self.metadata_with_port and key in self.metadata_with_port[port]:
                return self.metadata_with_port[port][key]
            elif key in self.metadata:
                return self.metadata[key]
            else:
                return None

        # count services with same name or no name
        names_count = defaultdict(lambda: 0)
        for port in self.ports:
            name = getattr('name', port.internal)
            if name:
                names_count[name] += 1

        services = list()
        for port in self.ports:
            service_name = getattr('name', port.internal)
            count = names_count[service_name]
            if count < 1:
                log.debug("Skipping port {}, no service name set".format(port))
                continue
            elif count > 1:
                service_name = '{}-{}'.format(service_name, port.external)
                if port.protocol != 'tcp':
                    service_name = '{}-{}'.format(service_name, port.protocol)

            service_tags = getattr('tags', port.internal) or []
            service_attrs = getattr('attrs', port.internal) or {}
            service_id = "{}:{}:{}".format(self.hostname, self.name, port.external)
            if port.protocol != 'tcp':
                service_id += ":" + port.protocol
                service_tags.append(port.protocol)
            if self.serviceid_prefix:
                service_id = "{}:{}".format(self.serviceid_prefix, service_id)
            service_ip = getattr('ip', port.internal) or self.serviceip
            service = Service(self.cid, service_id, service_name, service_ip,
                              port.external, tags=list(set(service_tags)), attrs=service_attrs)
            services.append(service)
        self._services = services
        return services

    def service_identifiers(self):
        return [service.id for service in self.services]


SERVICE_PORT_REGEX = re.compile(r'(?P<port>\d+)_(?P<key>.+)$')
SERVICE_KEY_REGEX = re.compile(r'SERVICE_(?P<key>.+)$')
SERVICE_KEYVAL_REGEX = re.compile(r'SERVICE_(?P<key>.+)=(?P<value>.*)$')

Ports = namedtuple('Ports', ('internal', 'external', 'protocol', 'ip'))


class ServiceRegistrator:

    def __init__(self, context):
        self.context = context
        self.hostname = socket.gethostname()
        log.info(context.options)
        log.info("Using IP: {}".format(context.options['ip']))
        log.info("Using docker socket: {}".format(context.options['dockersock']))

        self.consul_host = context.options['consul_host']
        self.consul_port = context.options['consul_port']
        log.info("Using Consul Agent at {}:{}".format(self.consul_host, self.consul_port))

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
        self.context.register_on_exit('close_events', close_events)

    def _init_consul(self):
        self.consul_client = consul.Consul(host=self.consul_host, port=self.consul_port)

        try:
            peers = self.consul_client.status.peers()
            log.info("Consul Agent has {} peers".format(len(peers)))
        except ConnectionError:
            log.error("Could not connect with Consul Agent.")
        except ConsulException as e:
            log.error("Consul issue: {}".format(e))

    def listen_events(self):
        yield from self.events

    def dump_events(self):
        # TODO: handle exceptions
        def fmtevent(action, etype, cid):
            return "Event [{}] type=[{}] cid=[{}]".format(action, etype, cid)

        for event in self.listen_events():
            if self.context.kill_now:
                break
            action = event['Action']
            etype = event['Type']
            cid = event['Actor']['ID']

            # with only listen for container events
            if etype != 'container':
                if self.context.options['debug']:
                    log.debug(fmtevent(action, etype, cid))
                continue

            # Ignore health checks
            if action.startswith("exec_"):
                if self.context.options['debug']:
                    log.debug(fmtevent(action, etype, cid))
                continue

            # Ignore image destroy (ecs does this regularly)
            if action == 'destroy':
                if self.context.options['debug']:
                    log.debug(fmtevent(action, etype, cid))
                continue

            log.info(fmtevent(action, etype, cid))

            container_info = self.parse_container_meta(cid)
            if not container_info:
                if self.context.options['debug']:
                    log.debug("skipping {} ...".format(cid))
                continue

            if cid in self.containers and action in ('pause', 'health_status: unhealthy', 'stop', 'die', 'kill', 'oom'):
                log.info(container_info)
                self.unregister(container_info)
                continue

            if action in ('health_status: healthy', 'start'):
                log.info(container_info)
                self.register(container_info)
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
            # no exposed or published ports, skip
            log.debug("skip container {} without exposed ports".format(cid))
            return None
        name = container.name
        container_info = ContainerInfo(cid, name, ports, metadata, metadata_with_port,
                                       self.hostname, self.context.options['ip'])
        if self.context.options['serviceid_prefix']:
            container_info.serviceid_prefix = self.context.options['serviceid_prefix']
        return container_info

    def docker_running_containers(self):
        return self.docker_client.containers.list(all=True, sparse=True, filters=dict(status='running'))

    def list_containers(self):
        for container in self.docker_running_containers():
            cid = container.id
            if cid not in self.containers:
                container.reload()  # needed since we use sparse, and want health
                container_info = self.parse_container_meta(cid)
                if container_info:
                    log.info(container_info)
                    self.register(container_info)
                elif container_info is not None:
                    log.debug("Skipping {}".format(container_info))
                else:
                    log.debug("Skipping {}".format(cid))
            else:
                log.debug("{} already in containers".format(cid))

    def make_check_http(self, service, params, proto='http'):
        """
        Consul HTTP Check

        This feature is only available when using Consul 0.5 or newer.
        Containers specifying these extra metadata in labels or environment will be used to register an HTTP health check with the service.

        SERVICE_80_CHECK_HTTP=/health/endpoint/path
        SERVICE_80_CHECK_INTERVAL=15s
        SERVICE_80_CHECK_TIMEOUT=1s		# optional, Consul default used otherwise
        SERVICE_80_CHECK_HTTP_METHOD=HEAD	# optional, Consul default used otherwise

        It works for services on any port, not just 80. If its the only service, you can also use SERVICE_CHECK_HTTP.

        Consul HTTPS Check

        This feature is only available when using Consul 0.5 or newer.
        Containers specifying these extra metedata in labels or environment will be used to register an HTTPS health check with the service.

        SERVICE_443_CHECK_HTTPS=/health/endpoint/path
        SERVICE_443_CHECK_INTERVAL=15s
        SERVICE_443_CHECK_TIMEOUT=1s		# optional, Consul default used otherwise
        SERVICE_443_CHECK_HTTPS_METHOD=HEAD	# optional, Consul default used otherwise
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L66
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-http-check
        # https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/consul/consul.go#L97
        path = params.get(proto, '')
        if path:
            """
            Perform a HTTP GET against *url* every *interval* (e.g. "10s") to perfom
            health check with an optional *timeout* and optional *deregister* after
            which a failing service will be automatically deregistered. Optional
            parameter *header* specifies headers sent in HTTP request. *header*
            paramater is in form of map of lists of strings,
            e.g. {"x-foo": ["bar", "baz"]}.
            """
            url = "{}://{}:{}{}".format(proto, service.ip, service.port, path)
            interval = params.get('interval', self.default_interval)
            timeout = params.get('timeout', None)
            deregister = params.get('deregister', None)
            if deregister:
                deregister = deregister.lower() == 'true'
            header = params.get('header', None)
            if header:
                try:
                    header = json.loads(header)
                except Exception as e:
                    log.error(e)
                    header = None
            return Check.http(url, interval, timeout=timeout, deregister=deregister, header=header)
        return None

    def make_check_tcp(self, service, params):
        """
        Consul TCP Check

        This feature is only available when using Consul 0.6 or newer.
        Containers specifying these extra metadata in labels or environment will be used to register an TCP health check with the service.

        SERVICE_443_CHECK_TCP=true
        SERVICE_443_CHECK_INTERVAL=15s
        SERVICE_443_CHECK_TIMEOUT=3s		# optional, Consul default used otherwise
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L85
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-tcp-check
        tcp = params.get('tcp', None)
        if tcp.lower() == 'true':
            """
            Attempt to establish a tcp connection to the specified *host* and
            *port* at a specified *interval* with optional *timeout* and optional
            *deregister* after which a failing service will be automatically
            deregistered.
            """
            host = service.ip
            port = service.port
            interval = params.get('interval', self.default_interval)
            timeout = params.get('timeout', None)
            deregister = params.get('deregister', None)
            if deregister:
                deregister = deregister.lower() == 'true'
            return Check.tcp(host, port, interval, timeout=timeout, deregister=deregister)
        return None

    def make_check_ttl(self, service, params):
        """
        Consul TTL Check

        You can also register a TTL check with Consul.
        Keep in mind, this means Consul will expect a regular heartbeat ping to its API to keep the service marked healthy.

        SERVICE_CHECK_TTL=30s
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L103
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-ttl-check
        ttl = params.get('ttl', None)
        if ttl:
            """
            Set check to be marked as critical after *ttl* (e.g. "10s") unless the
            check
            """
            return Check.ttl(ttl)
        return None

    def make_check_script(self, service, params):
        """
        Consul Script Check

        This feature is tricky because it lets you specify a script check to run from Consul. If running Consul in a container, you're limited to what you can run from that container. For example, curl must be installed for this to work:

        SERVICE_CHECK_SCRIPT=curl --silent --fail example.com

        The default interval for any non-TTL check is 10s, but you can set it with _CHECK_INTERVAL. The check command will be interpolated with the $SERVICE_IP and $SERVICE_PORT placeholders:

        SERVICE_CHECK_SCRIPT=nc $SERVICE_IP $SERVICE_PORT | grep OK
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L53
        # https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/consul/consul.go#L115
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-script-check
        args = params.get('script', None)
        if args:
            """
            Run the script *args* every *interval* (e.g. "10s") to perfom health check
            """
            args = args.replace('$SERVICE_IP', service.ip).replace('$SERVICE_PORT', service.port)
            interval = params.get('interval', self.default_interval)
            deregister = params.get('deregister', None)
            if deregister:
                deregister = deregister.lower() == 'true'
            return Check.script(args, interval, deregister=deregister)
        return None

    def make_check_docker(self, service, params):
        """
        Consul Docker Check

         SERVICE_CHECK_DOCKER=curl --silent --fail example.com
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L111
        script = params.get('docker', None)
        if script:
            """
            Invoke *script* packaged within a running docker container with
            *container_id* at a specified *interval* on the configured
            *shell* using the Docker Exec API.  Optional *register* after which a
            failing service will be automatically deregistered.
            """
            script = script.replace('$SERVICE_IP', service.ip).replace('$SERVICE_PORT', service.port)
            container_id = service.container_id[:12]
            shell = params.get('shell', '/bin/sh')
            interval = params.get('interval', self.default_interval)
            deregister = params.get('deregister', None)
            if deregister:
                deregister = deregister.lower() == 'true'
            return Check.docker(container_id, shell, script, interval, deregister=deregister)
        return None

    def make_check(self, service):
        self.default_interval = '10s'
        params = {}
        for key, value in service.attrs.items():
            if key.startswith('check_'):
                k = key[6:]
                params[k] = value
        if 'http' in params:
            return self.make_check_http(service, params, proto='http')
        if 'https' in params:
            return self.make_check_http(service, params, proto='https')
        if 'tcp' in params:
            return self.make_check_tcp(service, params)
        if 'script' in params:
            return self.make_check_script(service, params)
        if 'docker' in params:
            return self.make_check_docker(service, params)
        return None

    def consul_register_service(self, service):
        log.debug("consul register service {}".format(service.id))
        try:
            self.consul_client.agent.service.register(
                name=service.name,
                service_id=service.id,
                address=service.ip,
                port=service.port,
                tags=service.tags,
                meta=service.attrs,
                check=self.make_check(service)
            )
        except Exception as e:
            log.error(e)

    def consul_unregister_service(self, service_id):
        log.debug("consul unregister service {}".format(service_id))
        try:
            self.consul_client.agent.service.deregister(service_id)
        except Exception as e:
            log.error(e)

    def register_services(self, container_info):
        for service in container_info.services:
            self.consul_register_service(service)

    def unregister_services(self, container_info):
        for service in container_info.services:
            self.consul_unregister_service(service_id)

    def register(self, container_info):
        log.info('register {}'.format(container_info.name))
        self.containers[container_info.cid] = container_info
        self.register_services(container_info)

    def unregister(self, container_info):
        log.info('unregister {}'.format(container_info.name))
        try:
            del self.containers[container_info.cid]
            log.info('removing {} from containers'.format(container_info.name))
        except KeyError:
            pass
        self.unregister_services(container_info)

    def is_our_identifier(self, serviceid, prefix=''):
        identifier = serviceid.split(':')
        l = len(identifier)
        if l < 4:
            return False
        if prefix:
            if identifier[0] != prefix:
                return False
            else:
                identifier = identifier[1:]
                l -= 1
        if l > 4:
            return False
        if l == 4:
            if identifier[-1] != 'udp':
                return False
            else:
                identifier = identifier[:-1]
                l -= 1
        if l != 3:
            return False
        if identifier[0] != self.hostname:
            return False
        return True

    def containers_service_identifiers(self):
        services = []
        for cid, container_info in self.containers.items():
            services.extend(container_info.service_identifiers())
        return set(services)

    def consul_services(self):
        try:
            return self.consul_client.agent.services()
        except Exception as e:
            log.error(e)
            return {}

    def cleanup(self):
        log.debug("cleanup")
        registered_services = self.consul_services()
        our_services = self.containers_service_identifiers()
        prefix = self.context.options['serviceid_prefix']
        for serviceid in registered_services:
            if not self.is_our_identifier(serviceid, prefix):
                log.debug("cleanup: skipping {}, not ours".format(serviceid))
                continue
            if serviceid not in our_services:
                self.consul_unregister_service(serviceid)


class Context:
    kill_now = False
    on_exit = dict()
    _sig2name = None

    def __init__(self, options):
        self.options = options
        configure_logging(options)
        self.containers = {}

        # exit signals
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        # following signals may be used later
        signal.signal(signal.SIGHUP, self.ignore_signal)
        signal.signal(signal.SIGUSR1, self.ignore_signal)
        signal.signal(signal.SIGUSR2, self.ignore_signal)

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
@click.option('-dg', '--debug', is_flag=True, help='Enables debug mode')
@click.option('-sp', '--serviceid-prefix', default=None, help='service ID prefix (for testing purposes)')
@click.option('-ch', '--consul-host', default='127.0.0.1', help='consul agent host')
@click.option('-cp', '--consul-port', default=8500, type=click.INT, help='consul agent port')
def main(**options):
    """Register docker services into consul"""
    context = Context(options)

    while not context.kill_now:
        try:
            log.info("Starting...")
            serviceregistrator = ServiceRegistrator(context)
            serviceregistrator.list_containers()
            serviceregistrator.cleanup()
            serviceregistrator.dump_events()
        except docker.errors.DockerException as e:
            log.error(e)
        except Exception as e:
            log.error(e)
            log.error(traceback.format_exc())
        finally:
            if not context.kill_now:
                delay = context.options['delay']
                log.debug("sleeping {} second(s)...".format(delay))
                sleep(delay)


if __name__ == "__main__":
    main()
