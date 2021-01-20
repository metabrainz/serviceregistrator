# Service Object

ServiceRegistrator is primarily concerned with services that would be added to a
service discovery registry. In our case, a service is anything listening on a
port. If a container listens on multiple ports, it has multiple services.

Services are created with information from the container, including user-defined
metadata on the container, into an intermediary service object. This service
object is then passed to a registry backend to try and place as much of this
object into a particular registry.

## Container Overrides

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


## Detecting Services

ServiceRegistrator will only pick up services from containers that
have *explicitly published ports* (eg, using `-p` or `-P`).
For containers running in host network mode, it will pick *exposed ports*.

If no `SERVICE_NAME` or matching `SERVICE_<port>_NAME` can be found, service
will be skipped.

## IP

`-ip` option is mandatory.

It can be overridden by `SERVICE_IP` or `SERVICE_<port>_IP`

## Tags and Attributes

Tags and attributes are extra metadata fields for services.

Attributes can also be used for specifying Consul health checks.


## Unique ID

The ID is a cluster-wide unique identifier for this service instance. For the
most part, it's an implementation detail, as users typically use service names,
not their IDs. ServiceRegistrator comes up with a human-friendly string that
encodes useful information in the ID based on this pattern:

	<hostname>:<container-name>:<exposed-port>[:udp if udp]


## Examples

TODO
