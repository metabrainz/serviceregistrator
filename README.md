# serviceregistrator

A lightweight service registry bridge between Docker and [Consul](https://www.consul.io/).

ServiceRegistrator automatically registers and deregisters services in Consul
as Docker containers start and stop. It monitors the Docker event stream in
real-time and keeps Consul's service catalog in sync with the running
containers on a host.

## Why ServiceRegistrator?

This project is a Python re-implementation of
[Gliderlabs Registrator](https://github.com/gliderlabs/registrator), which is
no longer actively maintained. It is partly compatible with Registrator's
`SERVICE_*` environment variable syntax, making migration straightforward.

Key differences from Gliderlabs Registrator:

- **Explicit registration only**: containers must define a `SERVICE_NAME` (or
  `SERVICE_<port>_NAME`) to be registered. Unnamed services are skipped, giving
  you full control over what appears in Consul.
- **Written in Python**: easier to extend, debug, and contribute to.
- **Service aliases**: register a service under an additional name with an alias
  health check, useful for renaming services without breaking existing Consul
  templates.
- **Periodic resync**: optionally re-synchronize all services on a timer to
  recover from transient Consul issues.

## Use Cases

- **Dynamic service discovery**: automatically populate Consul's catalog so that
  load balancers, proxies, and other consumers can discover services by name.
- **Health-aware routing**: leverage Docker and Consul health checks so that
  only healthy containers receive traffic.
- **Zero-touch service lifecycle**: no manual Consul API calls needed — just
  start or stop containers and the catalog updates itself.
- **Gradual service renaming**: use aliases to introduce new service names while
  keeping the old ones working during a migration period.

## Install uv

https://docs.astral.sh/uv/getting-started/installation/

## Dev env

```bash
uv sync
```

```bash
uv run serviceregistrator --help
```

## Tests

Unit tests:

```bash
uv run pytest tests/
```

Integration tests (require Docker and pull a Consul image):

```bash
uv run pytest -m integration -v
```

All tests:

```bash
uv run pytest -m '' -v
```

Lint, format, and type checks:

```bash
uv run ruff check serviceregistrator tests
uv run ruff format --check serviceregistrator tests
uvx ty@0.0.29 check serviceregistrator
```

Manual end-to-end testing (see `testing/README.md`):

```bash
cd testing/dummyservice
./run_all.sh
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
- https://developer.hashicorp.com/consul/api-docs


# Usage

## Command-line

```
Usage: serviceregistrator [OPTIONS]

  Register docker containers as consul services

Options:
  -i, --ip TEXT                   address for services (IP or IP@TAG,
                                  repeatable)  [required]
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

## Configuring Services

ServiceRegistrator discovers services by reading `SERVICE_*` environment
variables and Docker labels on each container. These variables control what gets
registered in Consul and how.

### How It Works

1. A container must have **explicitly published ports** (`-p` or `-P`).
   For containers in host network mode, **exposed ports** (`EXPOSE`) are used.
2. A container must define a **`SERVICE_NAME`** (or `SERVICE_<port>_NAME` for a
   specific port). Containers without a name are skipped — nothing is registered.
3. ServiceRegistrator reads all `SERVICE_*` environment variables and labels,
   builds a service object for each named port, and registers it in Consul.

### `SERVICE_*` Variables

You can set these as either **environment variables** (`--env`) or **Docker
labels** (`--label`). Environment variables take precedence over labels when
both are set.

There are two forms:

- **`SERVICE_<KEY>=<value>`** — applies to all ports on the container (or the
  single exposed port).
- **`SERVICE_<port>_<KEY>=<value>`** — applies only to the service on that
  **internal** (container) port. Port-specific values override the generic ones.

The recognized keys are:

| Key     | Description                                              | Example                                |
|---------|----------------------------------------------------------|----------------------------------------|
| `NAME`  | **(Required)** Service name registered in Consul         | `SERVICE_NAME=postgres`                |
| `IP`    | Override the service IP address                          | `SERVICE_IP=10.0.0.5`                  |
| `TAGS`  | Comma-separated list of Consul tags                      | `SERVICE_TAGS=primary,db`              |
| `ALIAS` | Register an additional service name (see [Service Alias](#service-alias)) | `SERVICE_ALIAS=pg-master` |

Any other key is stored as a **service attribute** (key-value metadata):

```bash
SERVICE_REGION=us-east        # sets attr "region" = "us-east"
SERVICE_80_WEIGHT=10          # sets attr "weight" = "10" on port 80
```

Attributes are also used to configure [Consul health checks](#health-checks).

Container authors can set defaults in their Dockerfile; operators can override
them at `docker run` time.

### Example

```bash
docker run -d \
  --env "SERVICE_NAME=myapi" \
  --env "SERVICE_TAGS=web,public" \
  --env "SERVICE_80_CHECK_HTTP=/healthz" \
  --env "SERVICE_80_CHECK_INTERVAL=15s" \
  --publish "8080:80" \
  myimage
```

This registers a service named `myapi` in Consul at the host's IP on port 8080,
with tags `web` and `public`, and an HTTP health check hitting `/healthz` every
15 seconds.

For a multi-port container, use port-specific names:

```bash
docker run -d \
  --env "SERVICE_80_NAME=myapi" \
  --env "SERVICE_443_NAME=myapi-ssl" \
  --publish "8080:80" \
  --publish "8443:443" \
  myimage
```

### Service IP

The `--ip` flag sets the default address for services. It can be specified
multiple times and accepts an optional tag using the `IP@TAG` format:

```bash
serviceregistrator --ip 10.2.2.5                        # single IP, no tag
serviceregistrator --ip 10.2.2.5@physical               # single IP with tag
serviceregistrator --ip 10.2.2.5@physical --ip 10.10.10.5@virtual  # two IPs
```

The `@` separator is used instead of `:` to avoid conflicts with IPv6 addresses.

When multiple `--ip` values are given, containers that listen on all interfaces
(`0.0.0.0`) are registered once per `--ip` — creating multiple Consul service
instances under the same service name, each with its own IP and health check.
Containers that bind a specific IP are registered once with that IP.

When a tag is provided, it is:

- appended to the service's Consul tags (alongside `SERVICE_TAGS` and `--tags`)
- included in the service ID (e.g., `host:container:8090:physical`)

This lets consumers select a specific network using standard Consul mechanisms:

- DNS: `physical.myapi.service.consul`
- consul-template: `{{range service "myapi|physical"}}`
- API: `/v1/health/service/myapi?tag=physical`

The tag is always applied, even with a single `--ip`, enabling a smooth
migration path:

1. `--ip 10.2.2.5` — current setup, no change
2. `--ip 10.2.2.5@physical` — tag is added, consumers can start filtering
3. `--ip 10.2.2.5@physical --ip 10.10.10.5@virtual` — both networks active

Per-container overrides with `SERVICE_IP` or `SERVICE_<port>_IP` still work.
When a container overrides its IP, the tag from the matching `--ip` entry (if
any) is applied.

### Service Alias

You can register a service under an additional name using `SERVICE_ALIAS` or
`SERVICE_<port>_ALIAS`. This creates a second service in Consul with a
[Consul alias health check](https://developer.hashicorp.com/consul/api-docs/agent/check#aliasservice)
that mirrors the health of the original service.

This is useful for renaming services without breaking existing Consul template
files. For example:

```bash
docker run -d \
  --env "SERVICE_80_NAME=haproxy-postgres-primary" \
  --env "SERVICE_80_ALIAS=postgres-master" \
  --publish "5432:80" \
  myimage
```

This registers two services in Consul:

  - `haproxy-postgres-primary` — the real service with its normal health check
  - `postgres-master` — an alias that mirrors the health of `haproxy-postgres-primary`

Existing Consul template files using `{{if service "postgres-master"}}` will
continue to work while you migrate to the new naming convention.

The alias service inherits the same IP, port, and tags as the original service.
Its service ID has an `:alias` suffix appended.

### Health Checks

Health checks are configured through service attributes (the `SERVICE_*`
variables with check-related keys). The following check types are supported:

**HTTP / HTTPS check:**

```bash
SERVICE_80_CHECK_HTTP=/health        # path to check
SERVICE_80_CHECK_INTERVAL=15s        # check interval (default: 10s)
SERVICE_80_CHECK_TIMEOUT=2s          # request timeout
SERVICE_443_CHECK_HTTPS=/health      # same for HTTPS
SERVICE_443_CHECK_TLS_SKIP_VERIFY=true
```

**TCP check:**

```bash
SERVICE_5432_CHECK_TCP=true
SERVICE_5432_CHECK_INTERVAL=10s
SERVICE_5432_CHECK_TIMEOUT=3s
```

**TTL check:**

```bash
SERVICE_CHECK_TTL=30s
```

**Script check:**

```bash
SERVICE_CHECK_SCRIPT=curl --silent --fail http://$SERVICE_IP:$SERVICE_PORT/health
```

**Docker check:**

```bash
SERVICE_CHECK_DOCKER=curl --silent --fail http://localhost/health
```

Common check options:

| Key                    | Description                                          |
|------------------------|------------------------------------------------------|
| `CHECK_INTERVAL`       | Time between checks (default: `10s`)                 |
| `CHECK_TIMEOUT`        | Check timeout                                        |
| `CHECK_DEREGISTER`     | Deregister after being critical for this duration     |
| `CHECK_INITIAL_STATUS` | Initial check status (`passing`, `warning`, `critical`) |

### Service ID

The service ID is a cluster-wide unique identifier generated automatically:

    <hostname>:<container-name>:<exposed-port>[:udp if udp][:alias if alias][@tag if tagged]

When an `--ip` tag is set, it is appended to the ID (e.g.,
`host:myapp:8080@physical`). This is mostly an implementation detail — you
typically use service names, not IDs.

### Docker

Docker hub: https://hub.docker.com/repository/docker/metabrainz/serviceregistrator

Image tags:

  - latest: points to latest released version (vA.B.C)
  - vA.B.C: released version
  - edge: latest build

Images are automatically built and pushed using Git Workflow (in this repo).

#### Restart policy

Use `--restart always` (or `--restart unless-stopped`). If the Docker daemon
restarts, the mounted `/var/run/docker.sock` becomes stale and
ServiceRegistrator can no longer communicate with Docker. After 10 consecutive
failed connection attempts it exits so that the container restart policy can
re-create the container with a fresh socket mount.

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
