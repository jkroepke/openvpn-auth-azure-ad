# -*- coding: utf-8 -*-
import setuptools

from openvpn_auth_azure_ad._version import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="openvpn-auth-azure-ad",
    version=__version__,
    scripts=["openvpn_auth_azure_ad/openvpn-auth-azure-ad"],
    license="MIT",
    author="Jan-Otto Kröpke",
    author_email="pip@jkroepke.de",
    description="openvpn-auth-azure-ad connects to the openvpn management interface and handle the authentication "
    "ageist Azure AD.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jkroepke/openvpn-auth-azure-ad",
    download_url="https://github.com/jkroepke/openvpn-auth-azure-ad/archive/v%s.tar.gz"
    % __version__,
    packages=setuptools.find_packages(),
    keywords=["OpenVPN", "AzureAD", "authentication"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    install_requires=["msal", "cacheout", "ConfigArgParse", "prometheus_client"],
)
