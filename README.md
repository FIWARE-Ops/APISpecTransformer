![FIWARE Banner](https://nexus.lab.fiware.org/content/images/fiware-logo1.png)

# API Specification Transformer
[![Docker badge](https://img.shields.io/docker/pulls/fiware/service.apispectransformer.svg)](https://hub.docker.com/r/fiware/service.apispectransformer/)
[![Build Status](https://travis-ci.org/FIWARE-Ops/APISpecTransformer.svg?branch=master)](https://travis-ci.org/FIWARE-Ops/APISpecTransformer)

## Overview
This project is part of [FIWARE](https://fiware.org) OPS infrastructure.
It transforms API specifications into a defined format, applies some fixes and uploads the result to a specified GitHub repository under defined branches.
It works as a service and can receive GitHub notifications as well as direct requests.

## WARNING
Transformation temporary disabled.

## How to run
```console
$ docker run -e TOKEN_GITHUB=${TOKEN_GITHUB} \
             -p 0.0.0.0:${PORT}:${PORT} \
             fiware/service.apispectransformer \
             --ip 0.0.0.0 \
             --port ${PORT} \
             --config ${PATH_TO_CONFIG}
```       
```console      
$ curl http://localhost:${PORT}/ping
```
## How to configure
+ [APIMATIC Transformer](https://apimatic.io/transformer) is used to transform API specifications, so you should provide a valid token with an environment variable TOKEN_APIMATIC.
+ The result of transformation is uploaded to GitHub, so you should provide a valid token with an environment variable TOKEN_GITHUB.
+ Sample config is located [here](./config-example.json). 

## How to use
Ping
```console
$ curl http://localhost:${PORT}/ping
```
Get version
```console
$ curl http://localhost:${PORT}/version
```
Test APIMATIC connection, temporary disabled
```console
$ curl http://localhost:${PORT}/apimatic
```
Synchronize
```console
$ curl -XPOST http://localhost:${PORT}/sync?id=${REPOSITORY}
```

## GitHub integration
This project works as an endpoint and it should receive notifications from GitHub, so you should configure the webhook in the GitHub repository:
* application/json
* only push events
* no secrets
