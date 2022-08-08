[![CI](https://github.com/jkroepke/openvpn-auth-azure-ad/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-azure-ad/actions?query=workflow%3ACI)
[![PyPI](https://img.shields.io/pypi/v/openvpn-auth-azure-ad)](https://pypi.org/project/openvpn-auth-azure-ad/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/openvpn-auth-azure-ad)](https://pypi.org/project/openvpn-auth-azure-ad/)
[![Docker Pulls](https://img.shields.io/docker/pulls/jkroepke/openvpn-auth-azure-ad?logo=docker)](https://hub.docker.com/r/jkroepke/openvpn-auth-azure-ad)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-azure-ad)](https://github.com/jkroepke/openvpn-auth-azure-ad/blob/master/LICENSE.txt)

# openvpn-auth-azure-ad

State: Proof of concept!

openvpn-auth-azure-ad is an external service connects to the openvpn management interface and handle the authentication
of connecting users against Azure AD.

OpenVPN version 2.4 is required. 2.5 is not tested yet.

## Tested environment

### Python

- Python 3.8 / 3.10

### Server

- OpenVPN 2.5.6

### Client

- [OpenVPN Community Client for Windows 2.5.7](https://openvpn.net/community-downloads/)
- [Tunnelblick 3.8.7a](https://tunnelblick.net/)

# Authenticators

Currently, openvpn-auth-azure-ad supports 2 authentication method against Azure AD:

- [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
- [Resource Owner Password Credentials grant](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc)
  (not recommend, see docs for limitations)

Additionally, if enabled openvpn-auth-azure-ad supports OpenVPNs `auth-token` mechanismus to allow users to bypass
then authenticator above on re-authentications, e.g. due `reneg-sec`.

# Installation

## via pip

```
# pip install openvpn-auth-azure-ad
```

For install pip on your system, see [pip docs](https://pip.pypa.io/en/stable/installing/).

To run a persistent daemon, you copy the [systemd unit file](./contrib/openvpn-auth-azure-ad.service) to `/etc/systemd/system`, then
run

```bash
# systemctl enable openvpn-auth-azure-ad
# systemctl start openvpn-auth-azure-ad
```

## via docker

https://hub.docker.com/r/jkroepke/openvpn-auth-azure-ad

```
# docker run --rm \
    -v <path of openvpn mgmt socket>:/openvpn/management.sock
    -v /etc/openvpn-auth-azure-ad/config.conf:/etc/openvpn-auth-azure-ad/config.conf \
    -e AAD_CLIENT_ID= \
    -e OPENVPN_AAD_AUTH_SOCKET_PATH=/openvpn/management.sock \
    -e OPENVPN_AAD_AUTH_PASSWORD= \
    jkroepke/openvpn-auth-azure-ad
```

# Usage

Args that start with '--' (eg. -V) can also be set in a config file (/etc/openvpn-auth-azure-ad/config.conf or ~/.openvpn-auth-azure-ad or
specified via -c). Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). If an arg is
specified in more than one place, then commandline values override environment variables which override config file values which override defaults.

```
usage: openvpn-auth-azure-ad.py [-h] [-c CONFIG] [-V] [-t THREADS] [-a AUTHENTICATORS] [--auth-token] [--auth-token-lifetime AUTH_TOKEN_LIFETIME] [--remember-user] [--verify-openvpn-client]
                                [--verify-openvpn-client-id-token-claim] [-H OPENVPN_HOST] [-P OPENVPN_PORT] [-s OPENVPN_SOCKET] [-p OPENVPN_PASSWORD] [--openvpn-release-hold] --client-id CLIENT_ID
                                [--token-authority TOKEN_AUTHORITY] [--graph-endpoint GRAPH_ENDPOINT] [--prometheus] [--prometheus-listen-addr PROMETHEUS_LISTEN_ADDR]
                                [--prometheus-listen-port PROMETHEUS_LISTEN_PORT] [--log-level LOG_LEVEL]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        path of config file [env var: AAD_CONFIG_PATH]
  -V, --version         show program's version number and exit
  -t THREADS, --threads THREADS
                        Amount of threads to handle authentication [env var: AAD_THREAD_COUNT]

OpenVPN User Authentication:
  -a AUTHENTICATORS, --authenticators AUTHENTICATORS
                        Enable authenticators. Multiple authenticators can be separated with comma [env var: AAD_AUTHENTICATORS]
  --auth-token          Use auth token to re-authenticate clients [env var: AAD_AUTH_TOKEN]
  --auth-token-lifetime AUTH_TOKEN_LIFETIME
                        Lifetime of auth tokens in seconds [env var: AAD_AUTH_TOKEN_LIFETIME]
  --remember-user       If user authenticated once, the users refresh token is used to reauthenticate silently if possible. [env var: AAD_REMEMBER_USER]
  --verify-openvpn-client
                        Check if openvpn client common_name matches Azure AD token claim [env var: AAD_VERIFY_OPENVPN_CLIENT]
  --verify-openvpn-client-id-token-claim
                        AAD id_token claim used for client verification [env var: AAD_VERIFY_OPENVPN_CLIENT_ID_TOKEN_CLAIM]

OpenVPN Management Interface settings:
  -H OPENVPN_HOST, --openvpn-host OPENVPN_HOST
                        Host of OpenVPN management interface. [env var: OPENVPN_AAD_AUTH_HOST]
  -P OPENVPN_PORT, --openvpn-port OPENVPN_PORT
                        Port of OpenVPN management interface. [env var: OPENVPN_AAD_AUTH_PORT]
  -s OPENVPN_SOCKET, --openvpn-socket OPENVPN_SOCKET
                        Path of socket or OpenVPN management interface. [env var: OPENVPN_AAD_AUTH_SOCKET_PATH]
  -p OPENVPN_PASSWORD, --openvpn-password OPENVPN_PASSWORD
                        Passwort for OpenVPN management interface. [env var: OPENVPN_AAD_AUTH_PASSWORD]
  --openvpn-release-hold
                        Release hold on OpenVPN Server if --management-hold is enabled [env var: OPENVPN_AAD_AUTH_RELEASE_HOLD]

Azure AD settings:
  --client-id CLIENT_ID
                        Client ID of application. [env var: AAD_CLIENT_ID]
  --token-authority TOKEN_AUTHORITY
                        A URL that identifies a token authority. It should be of the format https://login.microsoftonline.com/your_tenant. By default, we will use https://login.microsoftonline.com/organizations
                        [env var: AAD_TOKEN_AUTHORITY]
  --graph-endpoint GRAPH_ENDPOINT
                        Endpoint of the graph API. See: https://developer.microsoft.com/en-us/graph/graph-explorer [env var: AAD_GRAPH_ENDPOINT]

Prometheus settings:
  --prometheus          Enable prometheus statistics [env var: AAD_PROMETHEUS_ENABLED]
  --prometheus-listen-addr PROMETHEUS_LISTEN_ADDR
                        prometheus listen addr [env var: AAD_PROMETHEUS_LISTEN_HOST]
  --prometheus-listen-port PROMETHEUS_LISTEN_PORT
                        prometheus statistics [env var: AAD_PROMETHEUS_PORT]
  --log-level LOG_LEVEL
                        Configure the logging level. [env var: AAD_LOG_LEVEL]
```

## Register an app with AAD

See: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app

#### TL;DR

1. Login as admin into tenant
2. Open [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) in Azure AD admin center
3. Click new registration
4. Pick a name, chose a "Supported account types"-option. Let the redirect uri blank and click register.
5. Copy the client-id. You need the client-id as configuration option for `openvpn-auth-azure-ad`.
6. Click on Authentication on the left menu
7. "Add a platform", pick Mobile and desktop applications and chose the "MSAL only" option.
8. On Advanced settings, set "Treat application as a public client" to yes.

## Required settings on OpenVPN configuration files

### server.conf

Use `auth-gen-token` only on OpenVPN 2.5+. It conflicts with `--auth-token`.

```
management socket-name unix [pw-file]
management-hold
management-client-auth
```

See [Reference manual for OpenVPN](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/)
for detailed `management` settings.

#### If no client certificate are required

If your setup does not require certificates, the following options are required:

```
username-as-common-name
```

### client.conf

```
auth-user-pass
auth-retry interact
```

`auth-user-pass` is always required otherwise dynamic challenges will not work.

# Prometheus support

openvpn-auth-azure-ad has some built-in prometheus support to collect some statistics about authenticators. By default,
the prometheus endpoint listen on port 9723.

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-azure-ad-auth

# Copyright and license

© [2022 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
