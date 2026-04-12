#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG=/tmp/serviceregistrator_test.log
CONSUL_PORT=8500
CONSUL_IMAGE="hashicorp/consul:1.15"
PASS=0
FAIL=0

cleanup() {
    echo "=== Cleanup ==="
    kill "$SR_PID" 2>/dev/null; wait "$SR_PID" 2>/dev/null || true
    for c in dummyservice8081 dummyservice8082 \
             dummyservice_checktcp dummyservice_checkhttp \
             dummyservice_checkscript dummyservice_checkscript2 \
             dummyservice_checkdocker dummyservice_alias \
             dummyservice_unhealthy dev-consul; do
        docker rm -f "$c" 2>/dev/null || true
    done
    rm -f "$LOG"
}
trap cleanup EXIT

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

check_log() {
    local desc="$1"
    local pattern="$2"
    check "$desc" grep -q "$pattern" "$LOG"
}

check_not_log() {
    local desc="$1"
    local pattern="$2"
    check "$desc" sh -c "! grep -q '$pattern' '$LOG'"
}

wait_for_log() {
    local pattern="$1"
    local timeout="${2:-30}"
    for i in $(seq 1 "$timeout"); do
        if grep -q "$pattern" "$LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

echo "=== Starting Consul ==="
docker rm -f dev-consul 2>/dev/null || true
docker run -d --name=dev-consul \
    -e CONSUL_BIND_INTERFACE=lo \
    -e 'CONSUL_LOCAL_CONFIG={"enable_script_checks": true}' \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --net=host "$CONSUL_IMAGE" >/dev/null

echo -n "Waiting for Consul..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:$CONSUL_PORT/v1/status/leader | grep -q 8300; then
        echo " ready"
        break
    fi
    sleep 1
done

echo "=== Starting serviceregistrator ==="
cd "$PROJECT_DIR"
uv run serviceregistrator --ip 127.0.0.1 --loglevel DEBUG > "$LOG" 2>&1 &
SR_PID=$!
sleep 2

echo "=== Building dummyservice image ==="
cd "$SCRIPT_DIR"
docker build -q . -t dummyservice >/dev/null

echo ""
echo "=== Test: basic service registration ==="
docker rm -f dummyservice_checktcp 2>/dev/null || true
docker run -d --name dummyservice_checktcp \
    --env "SERVICE_80_CHECK_TCP=true" \
    --env "SERVICE_80_CHECK_INTERVAL=10s" \
    --env "SERVICE_80_NAME=dummyservice_checktcp" \
    --publish "8083:80" \
    dummyservice >/dev/null
wait_for_log "REGISTER CHECK tcp for service.*dummyservice_checktcp"
check_log "TCP check registered" "REGISTER CHECK tcp for service.*dummyservice_checktcp"

echo ""
echo "=== Test: HTTP check ==="
docker rm -f dummyservice_checkhttp 2>/dev/null || true
docker run -d --name dummyservice_checkhttp \
    --env "SERVICE_80_CHECK_HTTP=/" \
    --env "SERVICE_80_CHECK_HTTP_METHOD=HEAD" \
    --env "SERVICE_80_CHECK_INTERVAL=5s" \
    --env "SERVICE_80_NAME=dummyservice_checkhttp" \
    --publish "8084:80" \
    dummyservice >/dev/null
wait_for_log "REGISTER CHECK http for service.*dummyservice_checkhttp"
check_log "HTTP check registered" "REGISTER CHECK http for service.*dummyservice_checkhttp"

echo ""
echo "=== Test: script check ==="
docker rm -f dummyservice_checkscript 2>/dev/null || true
docker run -d --name dummyservice_checkscript \
    --env "SERVICE_80_CHECK_SCRIPT=date -u -R" \
    --env "SERVICE_80_NAME=dummyservice_checkscript" \
    --publish "8085:80" \
    dummyservice >/dev/null
wait_for_log "REGISTER CHECK script for service.*dummyservice_checkscript"
check_log "Script check registered" "REGISTER CHECK script for service.*dummyservice_checkscript"

echo ""
echo "=== Test: docker check ==="
docker rm -f dummyservice_checkdocker 2>/dev/null || true
docker run -d --name dummyservice_checkdocker \
    --env "SERVICE_80_CHECK_DOCKER=/usr/sbin/nginx -T" \
    --env "SERVICE_80_NAME=dummyservice_checkdocker" \
    --publish "8086:80" \
    dummyservice >/dev/null
wait_for_log "REGISTER CHECK docker for service.*dummyservice_checkdocker"
check_log "Docker check registered" "REGISTER CHECK docker for service.*dummyservice_checkdocker"

echo ""
echo "=== Test: alias service ==="
docker rm -f dummyservice_alias 2>/dev/null || true
docker run -d --name dummyservice_alias \
    --env "SERVICE_80_NAME=haproxy-postgres-primary" \
    --env "SERVICE_80_ALIAS=postgres-master" \
    --env "SERVICE_80_CHECK_TCP=true" \
    --env "SERVICE_80_CHECK_INTERVAL=10s" \
    --publish "8089:80" \
    dummyservice >/dev/null
wait_for_log "REGISTER SERVICE.*name:postgres-master"
check_log "Alias service registered" "REGISTER SERVICE.*name:postgres-master"
check_log "Real service registered" "REGISTER SERVICE.*name:haproxy-postgres-primary"

echo ""
echo "=== Test: tags ==="
docker rm -f dummyservice8081 2>/dev/null || true
docker run -d --name dummyservice8081 \
    --env "SERVICE_80_NAME=dummyservice" \
    --env "SERVICE_TAGS=tag1,tag2" \
    --publish "8081:80" \
    dummyservice >/dev/null
wait_for_log "REGISTER.*dummyservice8081"
SERVICES=$(curl -sf http://127.0.0.1:$CONSUL_PORT/v1/agent/services)
check "Tags present in consul" sh -c "echo '$SERVICES' | grep -q tag1"

echo ""
echo "=== Test: container without SERVICE_NAME is skipped ==="
docker rm -f dummyservice8082 2>/dev/null || true
docker run -d --name dummyservice8082 \
    --publish "8082:80" \
    dummyservice >/dev/null
sleep 2
check_not_log "Container without SERVICE_NAME skipped" "REGISTER.*dummyservice8082"

echo ""
echo "=== Test: unhealthy container ==="
docker build -q -t dummyserviceunhealthy -f Dockerfile.unhealthy . >/dev/null
docker rm -f dummyservice_unhealthy 2>/dev/null || true
docker run -d --name dummyservice_unhealthy \
    --env "SERVICE_80_NAME=dummyservice_unhealthy" \
    --publish "8088:80" \
    dummyserviceunhealthy >/dev/null
wait_for_log "SKIPPED CONTAINER (unhealthy).*dummyservice_unhealthy" 30
check_log "Unhealthy container skipped" "SKIPPED CONTAINER (unhealthy).*dummyservice_unhealthy"

echo ""
echo "=== Test: health transition (unhealthy -> healthy) ==="
docker exec dummyservice_unhealthy mv -f /www/index.html.bak /www/index.html
wait_for_log "REGISTER CONTAINER.*dummyservice_unhealthy" 30
check_log "Container registered after becoming healthy" "REGISTER CONTAINER.*dummyservice_unhealthy"

echo ""
echo "=== Test: container removal triggers unregister ==="
docker rm -f dummyservice_checktcp >/dev/null
wait_for_log "UNREGISTER.*dummyservice_checktcp" 10
check_log "Service unregistered on container die" "UNREGISTER.*dummyservice_checktcp"

echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "================================"
[ "$FAIL" -eq 0 ]
