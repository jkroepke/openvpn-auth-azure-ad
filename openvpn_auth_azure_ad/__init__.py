from ._version import __version__

import logging
import os

import configargparse
import msal
from concurrent_log_handler.queue import setup_logging_queues
from prometheus_client import Info, start_http_server

from .authenticator import AADAuthenticator, AADAuthenticatorFlows


def main():
    parser = configargparse.ArgParser(
        default_config_files=[
            "/etc/openvpn-auth-azure-ad/config.conf",
            "~/.openvpn-auth-azure-ad",
        ]
    )

    parser.add_argument(
        "-c",
        "--config",
        is_config_file=True,
        help="path of config file",
        env_var="AAD_CONFIG_PATH",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )
    parser.add_argument(
        "-t",
        "--threads",
        default=10,
        env_var="AAD_THREAD_COUNT",
        help="Amount of threads to handle authentication",
        type=int,
    )

    parser_authentication = parser.add_argument_group("OpenVPN User Authentication")
    parser_authentication.add_argument(
        "-a",
        "--authenticators",
        default=AADAuthenticatorFlows.DEVICE_TOKEN,
        help="Enable authenticators. Multiple authenticators can be separated with comma",
        env_var="AAD_AUTHENTICATORS",
    )
    parser_authentication.add_argument(
        "--auth-token",
        action="store_true",
        help="Use auth token to re-authenticate clients",
        env_var="AAD_AUTH_TOKEN",
    )
    parser_authentication.add_argument(
        "--auth-token-lifetime",
        type=int,
        default=86400,
        help="Lifetime of auth tokens in seconds",
        env_var="AAD_AUTH_TOKEN_LIFETIME",
    )
    parser_authentication.add_argument(
        "--remember-user",
        action="store_true",
        help="If user authenticated once, the users refresh token is used to reauthenticate silently if possible.",
        env_var="AAD_REMEMBER_USER",
    )
    parser_authentication.add_argument(
        "--verify-openvpn-client",
        action="store_true",
        help="Check if openvpn client common_name matches Azure AD token claim",
        env_var="AAD_VERIFY_OPENVPN_CLIENT",
    )
    parser_authentication.add_argument(
        "--verify-openvpn-client-id-token-claim",
        action="store_true",
        default="preferred_username",
        help="AAD id_token claim used for client verification",
        env_var="AAD_VERIFY_OPENVPN_CLIENT_ID_TOKEN_CLAIM",
    )

    parser_openvpn = parser.add_argument_group("OpenVPN Management Interface settings")
    parser_openvpn.add_argument(
        "-H",
        "--openvpn-host",
        help="Host of OpenVPN management interface.",
        env_var="OPENVPN_AAD_AUTH_HOST",
    )
    parser_openvpn.add_argument(
        "-P",
        "--openvpn-port",
        help="Port of OpenVPN management interface.",
        env_var="OPENVPN_AAD_AUTH_PORT",
        type=int,
    )
    parser_openvpn.add_argument(
        "-s",
        "--openvpn-socket",
        help="Path of socket or OpenVPN management interface.",
        env_var="OPENVPN_AAD_AUTH_SOCKET_PATH",
    )
    parser_openvpn.add_argument(
        "-p",
        "--openvpn-password",
        help="Passwort for OpenVPN management interface.",
        env_var="OPENVPN_AAD_AUTH_PASSWORD",
    )
    parser_openvpn.add_argument(
        "--openvpn-release-hold",
        help="Release hold on OpenVPN Server if --management-hold is enabled",
        env_var="OPENVPN_AAD_AUTH_RELEASE_HOLD",
        action="store_true",
    )

    parser_aad = parser.add_argument_group("Azure AD settings")
    parser_aad.add_argument(
        "--client-id",
        required=True,
        help="Client ID of application.",
        env_var="AAD_CLIENT_ID",
    )
    parser_aad.add_argument(
        "--token-authority",
        default=os.environ.get(
            "authority", default="https://login.microsoftonline.com/organizations"
        ),
        env_var="AAD_TOKEN_AUTHORITY",
        help="A URL that identifies a token authority. It should be of the format "
        "https://login.microsoftonline.com/your_tenant. By default, we will use "
        "https://login.microsoftonline.com/organizations",
    )
    parser_aad.add_argument(
        "--graph-endpoint",
        default="https://graph.microsoft.com/v1.0/",
        env_var="AAD_GRAPH_ENDPOINT",
        help="Endpoint of the graph API. See: "
        "https://developer.microsoft.com/en-us/graph/graph-explorer",
    )

    parser_prometheus = parser.add_argument_group("Prometheus settings")
    parser_prometheus.add_argument(
        "--prometheus",
        action="store_true",
        env_var="AAD_PROMETHEUS_ENABLED",
        help="Enable prometheus statistics",
    )
    parser_prometheus.add_argument(
        "--prometheus-listen-addr",
        env_var="AAD_PROMETHEUS_LISTEN_HOST",
        default="",
        help="prometheus listen addr",
    )
    parser_prometheus.add_argument(
        "--prometheus-listen-port",
        type=int,
        env_var="AAD_PROMETHEUS_PORT",
        help=" prometheus statistics",
        default=9723,
    )
    parser_prometheus.add_argument(
        "--log-level",
        default=logging.INFO,
        type=lambda x: getattr(logging, x),
        env_var="AAD_LOG_LEVEL",
        help="Configure the logging level.",
    )

    options = parser.parse_args()

    # convert all configured loggers to use a background thread
    setup_logging_queues()

    logging.basicConfig(
        level=options.log_level, format="%(asctime)s %(levelname)s %(message)s"
    )

    if options.prometheus:
        start_http_server(
            options.prometheus_listen_port, options.prometheus_listen_addr
        )
        i = Info("openvpn_auth_azure_ad_version", "info of openvpn-auth-azure-ad")
        i.info({"version": __version__})

    app = msal.PublicClientApplication(
        options.client_id, authority=options.token_authority
    )

    aad_authenticator = AADAuthenticator(
        app,
        options.graph_endpoint,
        options.authenticators,
        options.verify_openvpn_client,
        options.verify_openvpn_client_id_token_claim,
        options.auth_token,
        options.auth_token_lifetime,
        options.remember_user,
        options.threads,
        options.openvpn_host,
        options.openvpn_port,
        options.openvpn_socket,
        options.openvpn_password,
        options.openvpn_release_hold,
    )

    aad_authenticator.run()
