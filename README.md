![FIWARE Banner](https://nexus.lab.fiware.org/static/images/fiware-logo1.png)

# API Specification Transformer
[![Docker badge](https://img.shields.io/docker/pulls/fiware/service.apispectransformer.svg)](https://hub.docker.com/r/fiware/service.apispectransformer/)

## Overview
This project is part of [FIWARE](https://fiware.org) OPS infrastructure.
It transforms API specifications into a defined format, applies some fixes and uploads the result to a specified GitHub repository under defined branches.
It works as a service and can receive GitHub notifications as well as direct requests.

## How to run
```console
$ docker run -e TOKEN=${TOKEN} \
             -e TOKEN_GITHUB=${TOKEN_GITHUB} \
             -e TOKEN_APIMATIC=${TOKEN_APIMATIC} \
             -p 0.0.0.0:${PORT}:${PORT} \
             fiware/service.apispectransformer \
             --ip 0.0.0.0 \
             --port ${PORT} \
             --config ${PATH_TO_CONFIG} \
             --user ${USER} \
             --email ${EMAIL} \
             --threads ${THREADS} \
             --socks ${SOCKS}
```       
```console      
$ curl http://localhost:8000/ping
```
## How to configure
+ [APIMATIC Transformer](https://apimatic.io/transformer) is used to transform API specifications, so you should provide a valid token with an environment variable TOKEN_APIMATIC.
+ The result of transformation is uploaded to GitHub, so you should provide a valid token with an environment variable TOKEN_GITHUB.
+ TOKEN is used to protect the API endpoint "/config", if not specified, the endpoint will be inaccessible.
+ Sample config is located [here](https://raw.githubusercontent.com/Fiware/service.APISpecTransformer/master/config-example.json). 

## How to use
Ping
```console
$ curl http://localhost:8000/ping
```
Get version
```console
$ curl http://localhost:8000/version
```
Get current config
```console
$ curl http://localhost:8000/config?token=${TOKEN}
```
Test APIMATIC connection
```console
$ curl http://localhost:8000/apimatic
```
Sync
```console
$ curl -X POST http://localhost:8000/sync?repo=${SOURCE_REPO_DEFINED_IN_CONFIG}
```

## GitHub integration
This project works as an endpoint and it should receive notifications from GitHub, so you should configure the webhook in the GitHub repository:
* application/json
* only push events
* no secrets
