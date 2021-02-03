#!/bin/bash

docker exec -it dummyservice_unhealthy mv -f /www/index.html.bak /www/index.html
