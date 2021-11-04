# serviceregistrator

An alternative to https://github.com/gliderlabs/registrator


## Install poetry

https://python-poetry.org/docs/#installation

## Dev env

```bash
poetry shell
```

```bash
poetry install
```

```bash
serviceregistrator --help
```

## Running in a docker container

### Build Image

```bash
docker build . -t serviceregistrator
```

### Running

```bash
docker run --rm serviceregistrator --help
```


## References

- https://docker-py.readthedocs.io/en/stable/
- https://python-consul2.readthedocs.io/en/latest/


# Usage

## Command-line

```
Usage: serviceregistrator [OPTIONS]

  Register docker containers as consul services

Options:
  -i, --ip TEXT                   address to use for services without
                                  SERVICE_IP  [required]
  -t, --tags TEXT                 comma-separated list of tags to append to
                                  all registered services
  -h, --consul-host TEXT          consul agent host  [default: 127.0.0.1]
  -p, --consul-port INTEGER       consul agent port  [default: 8500]
  -k, --dockersock TEXT           path to docker socket  [default:
                                  /var/run/docker.sock]
  -d, --delay INTEGER             delay in seconds between reconnection
                                  attempts  [default: 1]
  -s, --resync INTEGER            delay between each forced services resync
                                  [default: (disabled)]
  -f, --logfile TEXT              log file path
  -l, --loglevel [CRITICAL|ERROR|WARNING|INFO|DEBUG]
                                  log level  [default: INFO]
  -G, --debug                     output extra debug info
  -R, --debug-requests            log requests too (debug)
  -P, --service-prefix TEXT       string to prepend to all service names and
                                  IDs (testing purpose)
  --help                          Show this message and exit.
```

## Service Object

ServiceRegistrator is primarily concerned with services that would be added to a
service discovery registry. In our case, a service is anything listening on a
port. If a container listens on multiple ports, it has multiple services.

Services are created with information from the container, including user-defined
metadata on the container, into an intermediary service object. This service
object is then passed to a registry backend to try and place as much of this
object into a particular registry.

### Container Overrides

The fields `Name`, `Tags`, `Attrs`, and `ID` can be overridden by user-defined
container metadata. You can use environment variables or labels prefixed with
`SERVICE_` or `SERVICE_x_` to set values, where `x` is the internal exposed port.
For example `SERVICE_NAME=customerdb` and `SERVICE_80_NAME=api`.

You use a port in the key name to refer to a particular service on that port.
Metadata variables without a port in the name are used as the default for all
services or can be used to conveniently refer to the single exposed service.

The `Attrs` field is populated by metadata using any other field names in the
key name. For example, `SERVICE_REGION=us-east`.

Since metadata is stored as environment variables or labels, the container
author can include their own metadata defined in the Dockerfile. The operator
will still be able to override these author-defined defaults.


### Detecting Services

ServiceRegistrator will only pick up services from containers that
have *explicitly published ports* (eg, using `-p` or `-P`).
For containers running in host network mode, it will pick *exposed ports*.

**IMPORTANT**:
If no `SERVICE_NAME` or matching `SERVICE_<port>_NAME` can be found, service
will be skipped.
That's a main difference with registrator which registers everything it finds.

### IP

`-i/--ip` option is mandatory.

It can be overridden by `SERVICE_IP` or `SERVICE_<port>_IP`

### Tags and Attributes

Tags and attributes are extra metadata fields for services.

Attributes can also be used for specifying Consul health checks.


### Unique ID

The ID is a cluster-wide unique identifier for this service instance. For the
most part, it's an implementation detail, as users typically use service names,
not their IDs. ServiceRegistrator comes up with a human-friendly string that
encodes useful information in the ID based on this pattern:

	<hostname>:<container-name>:<exposed-port>[:udp if udp]

### Docker


Docker hub: https://hub.docker.com/repository/docker/metabrainz/serviceregistrator

Image tags:

  - latest: points to latest released version (vA.B.C)
  - vA.B.C: released version
  - edge: latest build

Images are automatically built and pushed using Git Workflow (in this repo).


#### Running (Host mode):

```bash
docker run \
  --detach \
  --restart unless-stopped \
  --name=serviceregistrator \
  --net=host \
  --volume=/var/run/docker.sock:/var/run/docker.sock \
  metabrainz/serviceregistrator:latest \
	--ip 127.0.0.1 \
	--consul-port 8500 \
	--consul-host localhost
```

#### Running (Network bridge mode):

```bash
docker run \
  --detach \
  --restart unless-stopped \
  --name=serviceregistrator \
  --add-host=host.docker.internal:host-gateway \
  --volume=/var/run/docker.sock:/var/run/docker.sock \
  metabrainz/serviceregistrator:latest \
	--ip 127.0.0.1 \
	--consul-port 8500 \
	--consul-host host.docker.internal
```

### Examples

See testing/dummyservice
