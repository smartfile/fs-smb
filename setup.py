#!/usr/bin/env python

import os

from setuptools import setup

readme_file = 'README.rst'
with open(os.path.join(os.path.dirname(__file__), readme_file)) as f:
    long_description = f.read()

setup(
    name='smbfs',
    version='0.2',
    packages=['smbfs'],
    description='A PyFilesystem backend for SMB shares.',
    long_description=long_description,
    install_requires=(
        'fs',
        'pysmb'
    ),
    author='Sean Farley',
    author_email='sean+dev@farley.org',
    maintainer='Sean Farley',
    maintainer_email='sean+dev@farley.org',
    url='http://github.com/smartfile/fs-smb/',
    license='BSD',
    package_data={'': [readme_file]},
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: BSD License',
    )
)
