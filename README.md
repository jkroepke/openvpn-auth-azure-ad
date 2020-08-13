# openvpn_aad_authenticator
openvpn_aad_authenticator connects to the openvpn management interface and handle the authentication ageist Azure AD.


# Settings on OpenVPN server

## server.conf
```
management socket-name unix [pw-file]
management-client-auth
```

## client.conf
```
auth-user-pass
auth-retry interact
```

See [Reference manual for OpenVPN](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/)
for detailed `management` settings. 
