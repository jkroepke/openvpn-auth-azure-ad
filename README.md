[![CI](https://github.com/jkroepke/openvpn-auth-azure-ad/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-azure-ad/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-azure-ad)](https://github.com/jkroepke/openvpn-auth-azure-ad/blob/master/LICENSE.txt)

# openvpn-auth-azure-ad

openvpn-auth-azure-ad is an external service connects to the openvpn management interface and handle the authentication
of connecting users against Azure AD.

## Version requirements

Server: 2.6
Client: 2.5

## Tested environment

### Server

- OpenVPN 2.6.0 on Linux

### Client

#### Working

- [OpenVPN Community Client for Windows 2.6.0](https://openvpn.net/community-downloads/)

#### Non-Working
-
- [Tunnelblick](https://tunnelblick.net/) - See https://github.com/Tunnelblick/Tunnelblick/issues/676

# Authenticators

Currently, openvpn-auth-azure-ad supports 2 authentication method against Azure AD:

- [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)

Additionally, if enabled openvpn-auth-azure-ad supports OpenVPNs `auth-token` mechanismus to allow users to bypass
then authenticator above on re-authentications, e.g. due `reneg-sec`.

# Installation

Go to down

# Usage

Args that start with '--' (eg. -V) can also be set in a config file (/etc/openvpn-auth-azure-ad/config.conf or ~/.openvpn-auth-azure-ad or
specified via -c). Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). If an arg is
specified in more than one place, then commandline values override environment variables which override config file values which override defaults.


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

```
script-security 3
auth-user-pass-verify "/usr/local/bin/openvpn-auth-azure-ad /etc/openvpn/openvpn-auth-azure-ad.yaml" via-file
auth-user-pass-optional
auth-gen-token
```

### client.conf

None


# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-azure-ad-auth

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
