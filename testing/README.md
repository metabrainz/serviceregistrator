# Manual testing

These scripts help test serviceregistrator manually against a real
Consul agent and Docker containers.

## Automated full test

Run all tests automatically (starts consul, serviceregistrator,
dummy containers, verifies behavior, and cleans up):

```bash
cd testing/dummyservice
./run_all.sh
```

## Step-by-step manual testing

## 1. Start a dev Consul agent

```bash
cd testing/dummyservice
./run_dev_consul.sh
```

Or with a specific version:

```bash
./run_dev_consul.sh 1.15
```

## 2. Start serviceregistrator

```bash
uv run serviceregistrator --ip 127.0.0.1
```

## 3. Start dummy service containers

```bash
cd testing/dummyservice
./run.sh
```

This starts several nginx containers with various `SERVICE_*`
configurations (TCP checks, HTTP checks, script checks, etc.).

For host network mode testing:

```bash
./run_host.sh
```

For unhealthy container testing:

```bash
./run_unhealthy.sh
```

## 4. Verify registration

```bash
./query_checks.sh
```

This queries the Consul API and shows registered services and checks.

You can also query directly:

```bash
curl -s http://127.0.0.1:8500/v1/agent/services | python3 -m json.tool
curl -s http://127.0.0.1:8500/v1/agent/checks | python3 -m json.tool
```

## 5. Test health transitions

Make the unhealthy container healthy:

```bash
./make_healthy.sh
```

Make it unhealthy again:

```bash
./make_unhealthy.sh
```

Watch serviceregistrator logs to see it react to health status changes.

## Cleanup

Stop serviceregistrator with `Ctrl+C`, then remove all test containers:

```bash
docker rm -f dummyservice8081 dummyservice8082 \
  dummyservice_checktcp dummyservice_checkhttp \
  dummyservice_checkscript dummyservice_checkscript2 \
  dummyservice_checkdocker dummyservice_alias \
  dummyservice_unhealthy \
  dummyservicehost1 dev-consul
```
