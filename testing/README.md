## Running a dev consul

```bash
docker rm -f dev-consul;
docker run -d --name=dev-consul -e CONSUL_BIND_INTERFACE=lo --network host consul
```

## testing

```
curl http://127.0.0.1:8500/v1/catalog/service/consul
```

```
docker exec -it dev-consul consul catalog services
```
