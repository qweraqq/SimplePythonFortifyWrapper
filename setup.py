#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import setuptools
from setuptools import setup

setup(
    name='SSCClient',
    version='0.0.1',
    author='xiangxiang.shen',
    author_email='admin@xiangxiang-shen.com',
    description="A simple requests-based python3 Fortify SSC client",
    url='https://xiangxiang-shen.com/',
    packages=setuptools.find_packages(),
    install_requires=[
          'requests',
      ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
