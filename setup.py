# -*- coding: utf-8 -*-
"""


"""

import sys

import setuptools

install_requires = [
]

tests_require = [
]

if sys.version_info < (2, 7):
    tests_require.append('unittest2')

setuptools.setup(
    name = 'yawsi',
    version = '0.0.1',
    description = '',
    keywords = (''),
    url = 'https://github.com/dangle/yawsi',
    download_url = 'git://github.com/dangle/yawsi.git',
    platform = ('any',),
    packages = setuptools.find_packages(),
    install_requires = install_requires,
    tests_require = tests_require,
    test_suite = 'tests',
    license = 'License :: OSI Approved :: MIT License',
    classifiers = (
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking'
    ),
)
