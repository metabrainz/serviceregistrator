#!/bin/bash

docker rm -f dev-consul

#note: enable_script_checks for testing only, unsecure
docker run -d --name=dev-consul -e CONSUL_BIND_INTERFACE=lo -e CONSUL_LOCAL_CONFIG='{"enable_script_checks": true}' --net=host consul
