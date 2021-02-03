#!/bin/bash

docker exec -it dummyservice_unhealthy mv -f /www/index.html /www/index.html.bak
