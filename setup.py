from setuptools import setup, find_packages
from codey.__about__ import *


setup(
    name=__title__,
    version=__version__,
    description=__summary__,
    url=__url__,
    author=__author__,
    author_email=__email__,
    license=__license__,
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    keywords='codey code encode decode cli',
    packages=find_packages(exclude=['tests*']),
    install_requires=[
        'pycryptodome'
    ],
    zip_safe=False,
    scripts=['bin/codey'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ]
)
