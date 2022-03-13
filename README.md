<p align="center">
<img src="https://github.com/tuxtof/cs-mikrotik-bouncer/raw/main/docs/assets/crowdsec_mikrotik_logo.png" alt="CrowdSec" title="CrowdSec" width="300" height="280" />
</p>

# CrowdSec Mikrotik Bouncer
A CrowdSec Bouncer for MikroTik RouterOS appliance

![GitHub](https://img.shields.io/github/license/tuxtof/cs-mikrotik-bouncer)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/tuxtof/cs-mikrotik-bouncer)
[![Go Report Card](https://goreportcard.com/badge/github.com/tuxtof/cs-mikrotik-bouncer)](https://goreportcard.com/report/github.com/tuxtof/cs-mikrotik-bouncer)
[![Maintainability](https://api.codeclimate.com/v1/badges/7177dce30f0abdf8bcbf/maintainability)](https://codeclimate.com/github/tuxtof/cs-mikrotik-bouncer/maintainability)
[![ci](https://github.com/tuxtof/cs-mikrotik-bouncer/actions/workflows/main.yml/badge.svg)](https://github.com/tuxtof/cs-mikrotik-bouncer/actions/workflows/main.yml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/tuxtof/cs-mikrotik-bouncer)
![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/tuxtof/cs-mikrotik-bouncer)

# Description
This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer for the router [Mikrotik](https://mikrotik.com) to block malicious IP to access your services.
For this it leverages [Mikrotik API](https://mikrotik.com) to populate a dynamic Firewall Address List.

# Install
## Prerequisites 
[Docker](https://docs.docker.com/get-docker/) and [Docker-compose](https://docs.docker.com/compose/install/) installed.   
You can use the docker-compose in the examples' folder as a starting point.
Through Mikrotik it exposes the whoami countainer on port 80, with the bouncer accepting and rejecting client IP.   
Launch your all services except the bouncer with the follow commands:
```bash
git clone https://github.com/tuxtof/cs-mikrotik-bouncer.git && \
  cd cs-mikrotik-bouncer/examples && \
  docker-compose up -d Mikrotik crowdsec whoami 
```

## Procedure
1. Get a bouncer API key from CrowdSec with command `docker exec crowdsec-example cscli bouncers add Mikrotik-bouncer`
2. Copy the API key printed. You **_WON'T_** be able the get it again.
3. Paste this API key as the value for bouncer environment variable `CROWDSEC_BOUNCER_API_KEY`, instead of "MyApiKey"
4. Start bouncer with `docker-compose up bouncer`


Enjoy!

# Usage
For now, this web service is mainly fought to be used as a container.   
If you need to build from source, you can get some inspiration from the Dockerfile.

## Prerequisites
You should have a Mikrotik appliance and a CrowdSec instance running.   
The container is available as docker image `tuxtof/cs-mikrotik-bouncer`. It must have access to CrowdSec and to Mikrotik.   

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add)

## Configuration
The webservice configuration is made via environment variables:

* `CROWDSEC_BOUNCER_API_KEY`            - CrowdSec bouncer API key required to be authorized to request local API (required)`
* `CROWDSEC_URL`                 - Host and port of CrowdSec agent, i.e. http://crowdsec:8080/ (required)`
* `CROWDSEC_BOUNCER_LOG_LEVEL`          - Minimum log level for bouncer. Expected value [zerolog levels](https://pkg.go.dev/github.com/rs/zerolog#readme-leveled-logging). Default to 1
* `MIKROTIK_HOST` - Mikrotik appliance address
* `MIKROTIK_USER` - Mikrotik appliance username
* `MIKROTIK_PASS` - Mikrotik appliance password


# Contribution
Any constructive feedback is welcome, fill free to add an issue or a pull request. I will review it and integrate it to the code.
