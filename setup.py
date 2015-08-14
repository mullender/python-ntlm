from setuptools import setup


long_description = """
This package allows Python clients running on any operating
system to provide NTLM authentication to a supporting server.

python-ntlm is probably most useful on platforms that are not
Windows, since on Windows it is possible to take advantage of
platform-specific NTLM support.

This is also useful for passing hashes to servers requiring
ntlm authentication in instances where using windows tools is
not desirable.
""".strip()


setup(
    name='python-ntlm',
    version='1.1.0',
    description='Python library that provides NTLM support, including an authentication handler for urllib2. Works with pass-the-hash in additon to password authentication.',
    long_description=long_description,
    author='Matthijs Mullender',
    author_email='info@zopyx.org',
    maintainer='Daniel Holth',
    maintainer_email='dholth@gmail.com',
    url="http://code.google.com/p/python-ntlm",
    packages=["ntlm"],
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "ntlm_example_simple=ntlm_examples.simple:main",
            "ntlm_example_extended=ntlm_examples.extended:main",
        ]
    },
    license="GNU Lesser GPL",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)"
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
)
