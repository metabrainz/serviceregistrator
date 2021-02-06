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
