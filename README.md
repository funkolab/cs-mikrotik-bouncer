<p align="center">
<img src="https://github.com/funkolab/cs-mikrotik-bouncer/raw/main/docs/assets/crowdsec_mikrotik_logo.png" alt="CrowdSec" title="CrowdSec" width="300" height="280" />
</p>

# CrowdSec Mikrotik Bouncer
A CrowdSec Bouncer for MikroTik RouterOS appliance

![GitHub](https://img.shields.io/github/license/funkolab/cs-mikrotik-bouncer)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/funkolab/cs-mikrotik-bouncer)
[![Go Report Card](https://goreportcard.com/badge/github.com/funkolab/cs-mikrotik-bouncer)](https://goreportcard.com/report/github.com/funkolab/cs-mikrotik-bouncer)
[![Maintainability](https://api.codeclimate.com/v1/badges/0104e64dccffc4b42f52/maintainability)](https://codeclimate.com/github/funkolab/cs-mikrotik-bouncer/maintainability)
[![ci](https://github.com/funkolab/cs-mikrotik-bouncer/actions/workflows/container-release.yaml/badge.svg)](https://github.com/funkolab/cs-mikrotik-bouncer/actions/workflows/container-release.yaml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/funkolab/cs-mikrotik-bouncer)
![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/funkolab/cs-mikrotik-bouncer)

# Description
This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer for the router [Mikrotik](https://mikrotik.com) to block malicious IP to access your services.
For this it leverages [Mikrotik API](https://mikrotik.com) to populate a dynamic Firewall Address List.


# Usage
For now, this web service is mainly fought to be used as a container.   
If you need to build from source, you can get some inspiration from the Dockerfile.


## Prerequisites
You should have a Mikrotik appliance and a CrowdSec instance running.   
The container is available as docker image `ghcr.io/funkolab/cs-mikrotik-bouncer` and `funkolab/cs-mikrotik-bouncer`. It must have access to CrowdSec and to Mikrotik.   

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add)

## Procedure
1. Get a bouncer API key from your CrowdSec with command `cscli bouncers add mikrotik-bouncer`
2. Copy the API key printed. You **_WON'T_** be able the get it again.
3. Paste this API key as the value for bouncer environment variable `CROWDSEC_BOUNCER_API_KEY`, instead of "MyApiKey"
4. Start bouncer with `docker-compose up bouncer` in the `example` directory
5. Create `IP drop Filter Rules` in `input` and `forward` Chain with the `crowdsec Source Address List`
6. Create `IPv6 drop Filter Rules` in `input` and `forward` Chain with the `crowdsec Source Address List` (if IPv6 used)

```shell
/ip/firewall/filter/
add action=drop src-address-list=crowdsec chain=input  in-interface=your-wan-interface place-before=0 comment="crowdsec input drop rules"
add action=drop src-address-list=crowdsec chain=forward in-interface=your-wan-interface place-before=0 comment="crowdsec forward drop rules"

/ipv6/firewall/filter/
add action=drop src-address-list=crowdsec chain=input  in-interface=your-wan-interface place-before=0 comment="crowdsec input drop rules"
add action=drop src-address-list=crowdsec chain=forward in-interface=your-wan-interface place-before=0 comment="crowdsec forward drop rules"
```

## Configuration
The bouncer configuration is made via environment variables:

| Name                       | Description                                                                                                        | Default                 | Required |
|----------------------------|--------------------------------------------------------------------------------------------------------------------|-------------------------|:--------:|
| `CROWDSEC_BOUNCER_API_KEY` | CrowdSec bouncer API key required to be authorized to request local API                                            | `none`                  |    ✅     |
| `CROWDSEC_URL`             | Host and port of CrowdSec agent                                                                                    | `http://crowdsec:8080/` |    ✅     |
| `LOG_LEVEL`                | Minimum log level for bouncer in [zerolog levels](https://pkg.go.dev/github.com/rs/zerolog#readme-leveled-logging) | `1`                     |    ❌     |
| `MIKROTIK_HOST`            | Mikrotik appliance address                                                                                         | `none`                  |    ✅     |
| `MIKROTIK_USER`            | Mikrotik appliance username                                                                                        | `none`                  |    ✅     |
| `MIKROTIK_PASS`            | Mikrotik appliance password                                                                                        | `none`                  |    ✅     |
| `MIKROTIK_TLS`             | User TLS to connect to Mikrotik API                                                                                | `true`                  |    ❌     |
| `MIKROTIK_IPV6`            | Enable / Disable IPv6 support                                                                                      | `true`                  |    ❌     |



# Contribution
Any constructive feedback is welcome, fill free to add an issue or a pull request. I will review it and integrate it to the code.
