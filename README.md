[![CI](https://github.com/jkroepke/openvpn-auth-azure-ad/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-azure-ad/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-azure-ad)](https://github.com/jkroepke/openvpn-auth-azure-ad/blob/master/LICENSE.txt)

# openvpn-auth-azure-ad

openvpn-auth-azure-ad is an program that gets executed by openvpn server and handle the authentication
of connecting users against Azure AD.

## Version requirements

Server: 2.6.0
Client: 2.5.0

## Tested environment

### Server

- OpenVPN 2.6.0 on Linux

### Client

#### Working

- [OpenVPN Community Client for Windows 2.6.0](https://openvpn.net/community-downloads/)

#### Non-Working
- [Tunnelblick](https://tunnelblick.net/) - See https://github.com/Tunnelblick/Tunnelblick/issues/676

# Installation

Go to https://github.com/jkroepke/openvpn-auth-azure-ad/releases/latest and download the binary to the openvpn server.

# Configuration

The binary must be callable by the unix user that runs the OpenVPN server.

A configuration file `/etc/openvpn/openvpn-auth-azure-ad.yaml` needs to be created, using follow pattern:

```yaml
azuread:
  clientId: 00000000-0000-0000-0000-000000000000 # App Registration Client ID
openvpn:
  urlHelper: https://jkroepke.github.io/openvpn-auth-azure-ad/
  # Should client certificates CN and Azure AD UPN match?
  matchUsernameClientCn: true
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

```
script-security 3
auth-user-pass-verify "/usr/local/bin/openvpn-auth-azure-ad /etc/openvpn/openvpn-auth-azure-ad.yaml" via-file
auth-user-pass-optional

# re-authenticate after 86400 seconds. Set 0 for no expiration.
auth-gen-token 86400
```

### client.conf

None


# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-azure-ad-auth

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
