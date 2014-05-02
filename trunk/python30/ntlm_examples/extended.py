"""
Usage:  extended.py <password> <url>

This downloads an NTML-protected webpage to stdout.  The username is
constructed from the USERDOMAIN and USERNAME environment variables.
Note that the password is entered on the command line; this is almost
certainly a security risk but unfortunately I know of no foolproof
method in Python for prompting for a password from standard input.

This script associates the password with all URLs using the same base
URI.  Although we only connect to a single URL, this would allow
access to all resources within a single domain.  This script also
allows the use of basic and digest authentication as well as NTML.
Finally, it disables the use of proxies, which would prevent it from
leaving most corporate domains (which typically route external
requests through a proxy server).
"""

import urllib.request, urllib.error, urllib.parse
from urllib.parse import urlparse, urlunparse
import inspect, os, sys

try:
    from ntlm import HTTPNtlmAuthHandler
except ImportError:
    # assume ntlm is in the directory "next door"
    ntlm_folder = os.path.realpath(os.path.join(
        os.path.dirname(inspect.getfile(inspect.currentframe())),
        '..'))
    sys.path.insert(0, ntlm_folder)
    from ntlm import HTTPNtlmAuthHandler

def process(password, url):
    user = '%s\%s' % ( os.environ["USERDOMAIN"], os.environ["USERNAME"] )

    # determine a base_uri for which the username and password can be used
    parsed_url = urlparse(url)
    base_uri = urlunparse((parsed_url[0],parsed_url[1],"","","",""))
    
    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, base_uri, user, password)
    # create the NTLM authentication handler
    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
    
    # other authentication handlers
    auth_basic = urllib.request.HTTPBasicAuthHandler(passman)
    auth_digest = urllib.request.HTTPDigestAuthHandler(passman)
    
    # disable proxies (if you want to stay within the corporate network)
    proxy_handler = urllib.request.ProxyHandler({})
    
    # create and install the opener
##    # Using auth_digest results in:
##    #   ValueError: AbstractDigestAuthHandler does not support the following scheme: 'NTLM'
##    # See http://bugs.python.org/issue21413
    urllib.request.install_opener(
        urllib.request.build_opener(
            proxy_handler,
            auth_NTLM,
##            auth_digest,
            auth_basic,
            ))
    
    # retrieve the result    
    response = urllib.request.urlopen(url)
    print((response.read()))

# The following is adapted from Guido van van Rossum's suggestion.
# http://www.artima.com/weblogs/viewpost.jsp?thread=4829

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

import sys
import getopt

def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "h", ["help"])
        except getopt.error as msg:
             raise Usage(msg)
        if opts:
            raise Usage(__doc__)
        if len(args) != 2:
            raise Usage('need exactly 2 arguments (%d given)' % len(args))
        process(*args)
    except Usage as err:
        print(err.msg, file=sys.stderr)
        if err.msg is not __doc__:
            print("for help use --help", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
