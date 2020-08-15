# openvpn-auth-azure-ad
openvpn-auth-azure-ad is an external service that
connects to the openvpn management interface and handle the authentication against Azure AD.

OpenVPN version 2.4 is required. 2.5 is not tested yet.

## Tested environment
## Server
* OpenVPN 2.4.9

## Client
* Tunnelblick 3.8.3

# Authenticators
Currently, openvpn-auth-azure-ad supports 2 authentication method against Azure AD:

* [Device token code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
* [Resource Owner Password Credentials grant](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc)
  (not recommend, see docs for limitations)

Additionally, if enabled openvpn-auth-azure-ad supports OpenVPNs `auth-token` mechanismus to allow users to bypass
then authenticator above on re-authentications, e.g. due `reneg-sec`.

# Installation

## via python-pip

```
# pip install openvpn-auth-azure-ad
```

For install pip on your system, see [pip docs](https://pip.pypa.io/en/stable/installing/).

## via docker

```
# docker run --rm \
    -v <path of openvpn mgmt socket>:/openvpn/management.sock
    -v /etc/openvpn-auth-azure-ad/config.conf:/etc/openvpn-auth-azure-ad/config.conf \
    -e AAD_CLIENT_ID= \
    -e AAD_OVPN_SOCKET_PATH=/openvpn/management.sock \
    -e AAD_OVPN_PASSWORD= \
    jkroepke/openvpn-auth-azure-ad
```

# Usage

Args that start with '--' (eg. -V) can also be set in a config file (/etc/openvpn-auth-azure-ad/config.conf or ~/.openvpn-auth-azure-ad or
specified via -c). Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). If an arg is
specified in more than one place, then commandline values override environment variables which override config file values which override defaults.

```
usage: openvpn-auth-azure-ad [-h] [-c CONFIG] [-V] [-a AUTHENTICATORS] [--auth-token] [-H OVPN_HOST] [-P OVPN_PORT] [-s OVPN_SOCKET]
                             [-p OVPN_PASSWORD] --client-id CLIENT_ID [--token-authority TOKEN_AUTHORITY] [--graph-endpoint GRAPH_ENDPOINT]
                             [--prometheus] [--prometheus-listen-addr PROMETHEUS_LISTEN_ADDR] [--prometheus-listen-port PROMETHEUS_LISTEN_PORT]
                             [--log-level LOG_LEVEL]

Args that start with '--' (eg. -V) can also be set in a config file (/etc/openvpn-auth-azure-ad/config.conf or ~/.openvpn-auth-azure-ad or specified
via -c). Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). If an arg is specified in
more than one place, then commandline values override environment variables which override config file values which override defaults.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        path of config file [env var: AAD_CONFIG_PATH]
  -V, --version         show program's version number and exit
  -a AUTHENTICATORS, --authenticators AUTHENTICATORS
                        Enable authenticators. Multiple authenticators can be separated with comma [env var: AAD_AUTHENTICATORS]
  --auth-token          Use auth token to re-authenticate clients [env var: AAD_AUTH_TOKEN]

OpenVPN Management Interface settings:
  -H OVPN_HOST, --ovpn-host OVPN_HOST
                        Host of OpenVPN management interface. [env var: AAD_OVPN_HOST]
  -P OVPN_PORT, --ovpn-port OVPN_PORT
                        Port of OpenVPN management interface. [env var: AAD_OVPN_PORT]
  -s OVPN_SOCKET, --ovpn-socket OVPN_SOCKET
                        Path of socket or OpenVPN management interface. [env var: AAD_OVPN_SOCKET_PATH]
  -p OVPN_PASSWORD, --ovpn-password OVPN_PASSWORD
                        Passwort for OpenVPN management interface. [env var: AAD_OVPN_PASSWORD]

Azure AD settings:
  --client-id CLIENT_ID
                        Client ID of application. [env var: AAD_CLIENT_ID]
  --token-authority TOKEN_AUTHORITY
                        A URL that identifies a token authority. It should be of the format https://login.microsoftonline.com/your_tenant. By default,
                        we will use https://login.microsoftonline.com/organizations [env var: AAD_TOKEN_AUTHORITY]
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

## Required settings on OpenVPN configuration files

### server.conf
```
management socket-name unix [pw-file]
management-client-auth
```

See [Reference manual for OpenVPN](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/)
for detailed `management` settings.

### client.conf
```
auth-user-pass
auth-retry interact
```

`auth-user-pass` is required even if the `username_password` authenticator is disabled. Otherwise the dynamic challenges
will not work.

## Prometheus support

openvpn-auth-azure-ad has some built-in prometheus support to collect some statistics about authenticators. By default
the prometheus endpoint listen on port 9723.

## Related projects

* https://github.com/CyberNinjas/openvpn-auth-aad
* https://github.com/stilljake/openvpn-azure-ad-auth

## Copyright and license
© [2020 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
