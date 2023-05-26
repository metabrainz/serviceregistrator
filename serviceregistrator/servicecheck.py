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

from consul import Check
import json
import logging
import shlex


log = logging.getLogger('serviceregistrator')


class ServiceCheck:
    defaults = {
        'body': None,
        'deregister': None,
        'docker': None,
        'header': None,
        'http': '',
        'https': '',
        'http_method': None,
        'https_method': None,
        'initial_status': None,
        'interval': '10s',
        'shell': '/bin/sh',
        'script': None,
        'tcp': None,
        'timeout': None,
        'tls_skip_verify': None,
        'ttl': None,
    }

    consul_version = (0, 0, 0)

    @classmethod
    def _value(cls, params, key):
        return params.get(key, cls.defaults.get(key))

    @classmethod
    def _common_values(cls, params):
        interval = cls._value(params, 'interval')
        deregister = cls._value(params, 'deregister')
        return interval, deregister

    @classmethod
    def _json_value(cls, params, key):
        value = cls._value(params, key)
        if value:
            try:
                return json.loads(value)
            except Exception as e:
                log.error(e)
        return None

    @classmethod
    def _bool_value(cls, params, key):
        value = cls._value(params, key)
        return value and value.lower() == 'true'

    @classmethod
    def _post_process(cls, checkret, params):
        # https://www.consul.io/api-docs/agent/check#status
        # https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/docs/user/backends.md#consul-initial-health-check-status
        initial_status = cls._value(params, 'initial_status')
        if initial_status:
            checkret['Status'] = initial_status
        return checkret

    @classmethod
    def _http(cls, service, params, proto='http'):
        """
        Consul HTTP Check

        This feature is only available when using Consul 0.5 or newer.
        Containers specifying these extra metadata in labels or environment will
        be used to register an HTTP health check with the service.

        SERVICE_80_CHECK_HTTP=/health/endpoint/path
        SERVICE_80_CHECK_INTERVAL=15s
        SERVICE_80_CHECK_TIMEOUT=1s		# optional, Consul default used otherwise

        It works for services on any port, not just 80.
        If its the only service, you can also use SERVICE_CHECK_HTTP.

        Consul HTTPS Check

        This feature is only available when using Consul 0.5 or newer.
        Containers specifying these extra metedata in labels or environment will
        be used to register an HTTPS health check with the service.

        SERVICE_443_CHECK_HTTPS=/health/endpoint/path
        SERVICE_443_CHECK_INTERVAL=15s
        SERVICE_443_CHECK_TIMEOUT=1s		# optional, Consul default used otherwise
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L66
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-http-check
        # https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/consul/consul.go#L97
        # https://github.com/poppyred/python-consul2/blob/b1057552427ccad11c03f7d60743336f77d0f7ea/consul/base.py#L66
        # https://www.consul.io/docs/discovery/checks#http-interval
        path = cls._value(params, proto)
        if path:
            # Perform a HTTP GET against *url* every *interval* (e.g. "10s") to perfom
            # health check with an optional *timeout* and optional *deregister* after
            # which a failing service will be automatically deregistered. Optional
            # parameter *header* specifies headers sent in HTTP request. *header*
            # paramater is in form of map of lists of strings,
            # e.g. {"x-foo": ["bar", "baz"]}.
            url = f"{proto}://{service.ip}:{service.port}{path}"
            timeout = cls._value(params, 'timeout')
            interval, deregister = cls._common_values(params)
            tls_skip_verify = cls._bool_value(params, 'tls_skip_verify')
            header = cls._json_value(params, 'header')
            ret = Check.http(url, interval, timeout=timeout, deregister=deregister,
                             header=header, tls_skip_verify=tls_skip_verify)
            method = cls._value(params, proto + '_method')
            if method:
                if cls.consul_version <= (0, 8, 5):
                    # method was buggy before that
                    # https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#085-june-27-2017
                    return None
                # FIXME: as 2021/01/20, python-consul doesn't support setting method
                # https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#084-june-9-2017
                ret['Method'] = method.upper()
            body = cls._value(params, 'body')
            if body:
                if cls.consul_version < (1, 7, 0):
                    # not implemented before 1.7.0
                    return None
                # consul >= 1.7.0
                # https://github.com/hashicorp/consul/pull/6602
                # https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#170-february-11-2020
                ret['Body'] = body
            return cls._post_process(ret, params)
        return None

    @classmethod
    def http(cls, service, params):
        return cls._http(service, params, proto='http')

    @classmethod
    def https(cls, service, params):
        return cls._http(service, params, proto='https')

    @classmethod
    def tcp(cls, service, params):
        """
        Consul TCP Check

        This feature is only available when using Consul 0.6 or newer.
        Containers specifying these extra metadata in labels or environment will be used to register
        an TCP health check with the service.

        SERVICE_443_CHECK_TCP=true
        SERVICE_443_CHECK_INTERVAL=15s
        SERVICE_443_CHECK_TIMEOUT=3s		# optional, Consul default used otherwise
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L85
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-tcp-check
        tcp = cls._bool_value(params, 'tcp')
        if tcp:
            # Attempt to establish a tcp connection to the specified *host* and
            # *port* at a specified *interval* with optional *timeout* and optional
            # *deregister* after which a failing service will be automatically
            # deregistered.
            host = service.ip
            port = service.port
            interval, deregister = cls._common_values(params)
            timeout = cls._value(params, 'timeout')
            ret = Check.tcp(host, port, interval, timeout=timeout, deregister=deregister)
            return cls._post_process(ret, params)
        return None

    @classmethod
    def ttl(cls, service, params):
        """
        Consul TTL Check

        You can also register a TTL check with Consul.
        Keep in mind, this means Consul will expect a regular heartbeat ping to its API to keep the service
        marked healthy.

        SERVICE_CHECK_TTL=30s
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L103
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-ttl-check
        ttl = cls._value(params, 'ttl')
        if ttl:
            # Set check to be marked as critical after *ttl* (e.g. "10s") unless the
            # check
            ret = Check.ttl(ttl)
            return cls._post_process(ret, params)
        return None

    @classmethod
    def script(cls, service, params):
        """
        Consul Script Check

        This feature is tricky because it lets you specify a script check to run from Consul.
        If running Consul in a container, you're limited to what you can run from that container.
        For example, curl must be installed for this to work:

        SERVICE_CHECK_SCRIPT=curl --silent --fail example.com

        The default interval for any non-TTL check is 10s, but you can set it with _CHECK_INTERVAL.
        The check command will be interpolated with the $SERVICE_IP and $SERVICE_PORT placeholders:

        SERVICE_CHECK_SCRIPT=nc $SERVICE_IP $SERVICE_PORT | grep OK
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L53
        # https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/consul/consul.go#L115
        # https://github.com/gliderlabs/registrator/blob/master/docs/user/backends.md#consul-script-check
        # https://www.consul.io/docs/agent/options#_enable_script_checks
        # https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations
        args = cls._value(params, 'script')
        if args:
            # Run the script *args* every *interval* (e.g. "10s") to perfom health check
            args = args.replace('$SERVICE_IP', service.ip).replace('$SERVICE_PORT', str(service.port))
            interval = cls._value(params, 'interval')
            if cls.consul_version >= (1, 1, 0):
                ret = Check.script(shlex.split(args), interval)
                return cls._post_process(ret, params)
            else:
                # compat
                # https://github.com/cablehead/python-consul/commit/f405dee1beb6019986307c121702d2e9ad40bcda
                # https://github.com/cablehead/python-consul/commit/e3493a0e6089d01ae37347f452cf7510813e2eb4
                ret = Check.script(args, interval)
                ret['script'] = args
                del ret['args']
                return cls._post_process(ret, params)
        return None

    @classmethod
    def docker(cls, service, params):
        """
        Consul Docker Check

         SERVICE_CHECK_DOCKER=curl --silent --fail example.com
        """
        # https://github.com/cablehead/python-consul/blob/53eb41c4760b983aec878ef73e72c11e0af501bb/consul/base.py#L111
        # https://www.consul.io/docs/discovery/checks#docker-interval
        #
        # NOTE: consul agent should be able to access docker socket: -v /var/run/docker.sock:/var/run/docker.sock
        script = cls._value(params, 'docker')
        if script:
            # Invoke *script* packaged within a running docker container with
            # *container_id* at a specified *interval* on the configured
            # *shell* using the Docker Exec API.  Optional *register* after which a
            # failing service will be automatically deregistered.
            script = script.replace('$SERVICE_IP', service.ip).replace('$SERVICE_PORT', str(service.port))
            container_id = service.container_id[:12]
            shell = cls._value(params, 'shell')
            interval, deregister = cls._common_values(params)
            ret = Check.docker(container_id, shell, script, interval, deregister=deregister)
            # FIXME: as 2021/01/24, python-consul2 uses old script instead of args
            # it was removed in consul 1.1.0
            # https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#110-may-11-2018
            if cls.consul_version >= (1, 1, 0):
                ret['args'] = shlex.split(script)
                del ret['script']
            return cls._post_process(ret, params)
        return None
