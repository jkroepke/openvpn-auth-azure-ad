import setuptools
with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='openvpn_aad_authenticator',
    version='0.1',
    scripts=['openvpn_aad_authenticator'],
    licence='MIT',
    author='Jan-Otto Kröpke',
    author_email='pip@jkroepke.de',
    description='openvpn_aad_authenticator connects to the openvpn management interface and handle the authentication '
                'ageist Azure AD.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/jkroepke/openvpn_aad_authenticator',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
    install_requires=['msal', 'cacheout', 'PyYAML']
)
