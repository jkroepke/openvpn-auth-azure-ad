import logging
import os

import configargparse
import msal
from concurrent_log_handler.queue import setup_logging_queues
from prometheus_client import Info, start_http_server

from ._version import __version__
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
        "--auth-token-livetime",
        type=int,
        default=86400,
        help="Livetime of auth tokens in seconds",
        env_var="AAD_AUTH_TOKEN_LIFETIME",
    )
    parser_authentication.add_argument(
        "--remember-user",
        action="store_true",
        help="If user authenticated once, the users refresh token is used to reauthenticate silently if possible.",
        env_var="AAD_REMEMBER_USER",
    )
    parser_authentication.add_argument(
        "--verify-common-name",
        action="store_true",
        help="Check if common_name matches Azure AD UPN",
        env_var="AAD_VERIFY_COMMON_NAME",
    )

    parser_openvpn = parser.add_argument_group("OpenVPN Management Interface settings")
    parser_openvpn.add_argument(
        "-H",
        "--ovpn-host",
        help="Host of OpenVPN management interface.",
        env_var="AAD_OVPN_HOST",
    )
    parser_openvpn.add_argument(
        "-P",
        "--ovpn-port",
        help="Port of OpenVPN management interface.",
        env_var="AAD_OVPN_PORT",
        type=int,
    )
    parser_openvpn.add_argument(
        "-s",
        "--ovpn-socket",
        help="Path of socket or OpenVPN management interface.",
        env_var="AAD_OVPN_SOCKET_PATH",
    )
    parser_openvpn.add_argument(
        "-p",
        "--ovpn-password",
        help="Passwort for OpenVPN management interface.",
        env_var="AAD_OVPN_PASSWORD",
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

    authenticator = AADAuthenticator(
        app,
        options.graph_endpoint,
        options.authenticators,
        options.verify_common_name,
        options.auth_token,
        options.auth_token_livetime,
        options.remember_user,
        options.threads,
        options.ovpn_host,
        options.ovpn_port,
        options.ovpn_socket,
        options.ovpn_password,
    )

    authenticator.run()
