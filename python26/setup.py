from setuptools import setup, find_packages
import os
import sys

SRC_FOLDER = "src"

ENTRY_POINTS = { "console_scripts":[ "ntlm_example_simple=ntlm_examples.simple:main",
                                     "ntlm_example_extended=ntlm_examples.extended:main",] }

DEPENDENCIES = []

if sys.version_info < ( 2,5 ):
    DEPENDENCIES.append( "hashlib" )
    
setup(name='python-ntlm',
      version='1.0',
      description='Python library that provides NTLM support, including an authentication handler for urllib2.',
      long_description="""
      This package allows Python clients running on any operating
      system to provide NTLM authentication to a supporting server.
      
      python-ntlm is probably most useful on platforms that are not
      Windows, since on Windows it is possible to take advantage of
      platform-specific NTLM support.""",
      author='Matthijs Mullender',
      maintainer='Daniel Holth',
      maintainer_email='dholth@gmail.com',
      url="http://code.google.com/p/python-ntlm",
      packages=["ntlm",],
      zip_safe=False,
      entry_points = ENTRY_POINTS,
      install_requires = DEPENDENCIES,
      )
