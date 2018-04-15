#!/usr/bin/python

from setuptools import setup
from pamphlet_cffi import ffi

setup(name = "pamphlet",
      version = "1.2",
      author = "Dennis Kaarsemaker",
      author_email = "dennis@kaarsemaker.net",
      url = "http://github.com/seveas/pamphlet",
      description = "Linux PAM bindings for python",
      py_modules = ["pamphlet"],
      ext_modules = [ffi.distutils_extension()],
      classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: zlib/libpng License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
      ],
      install_requires = ['six', 'cffi'],
)
