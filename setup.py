import setuptools

from version import __version__
from pip._internal.req import parse_requirements


def load_requirements(fname):
    reqs = parse_requirements(fname, session="test")
    return [str(ir.req) for ir in reqs]


with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='openvpn_aad_authenticator',
    version=__version__,
    scripts=['openvpn_aad_authenticator'],
    license='MIT',
    author='Jan-Otto Kröpke',
    author_email='pip@jkroepke.de',
    description='openvpn_aad_authenticator connects to the openvpn management interface and handle the authentication '
                'ageist Azure AD.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/jkroepke/openvpn_aad_authenticator',
    download_url='https://github.com/jkroepke/helm-openvpn_aad_authenticator/archive/v%s.tar.gz' % __version__,
    packages=setuptools.find_packages(),
    keywords=['OpenVPN', 'AzureAD', 'authentication'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
    install_requires=['msal', 'cacheout', 'ConfigArgParse', 'prometheus_client']
)
