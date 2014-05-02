"""\
Demonstrate various defects (or their repair!) in the ntml module.
"""


from io import BytesIO
import http.client
import inspect, os, sys
import traceback
import urllib.request, urllib.error, urllib.parse
try:
    from ntlm import HTTPNtlmAuthHandler
except ImportError:
    # assume ntlm is in the directory "next door"
    ntlm_folder = os.path.realpath(os.path.join(
        os.path.dirname(inspect.getfile(inspect.currentframe())),
        '..'))
    sys.path.insert(0, ntlm_folder)
    from ntlm import HTTPNtlmAuthHandler


# The headers seen during an initial NTML rejection.
initial_rejection = b'''HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM
Connection: close
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

'''


# The headers and data seen following a successful NTML connection.
eventual_success = b'''HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

Hello, world!'''


# A collection of transactions representing various defects in NTLM
# processing. Each is indexed according the the issues number recorded
# for the defect at code.google.com, and consists of a series of server
# responses that should be seen as a connection is attempted.
issues = {
    27: [
        initial_rejection,
        b'''HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA
WWW-Authenticate: Negotiate
Content-Length: 0
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

''',
        eventual_success,
        ],
    28: [
        initial_rejection,
        b'''HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAABAgAAO/AU3OJc3g0=
Content-Length: 0
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

''',
        eventual_success,
        ],
    }


class FakeSocket(BytesIO):
    '''Extends BytesIO just enough to look like a socket.'''
    def makefile(self, *args, **kwds):
        '''The instance already looks like a file.'''
        return self
    def sendall(self, *args, **kwds):
        '''Ignore any data that may be sent.'''
        pass
    def close(self):
        '''Ignore any calls to close.'''
        pass


class FakeHTTPConnection(http.client.HTTPConnection):
    '''Looks like a normal HTTPConnection, but returns a FakeSocket.
    The connection's port number is used to choose a set of transactions
    to replay to the user.  A class static variable is used to track
    how many transactions have been replayed.'''
    attempt = {}
    def connect(self):
        '''Returns a FakeSocket containing the data for a single
        transaction.'''
        nbr = self.attempt.setdefault(self.port, 0)
        self.attempt[self.port] = nbr + 1
        print('connecting to %s:%s (attempt %s)' % (self.host, self.port, nbr))
        self.sock = FakeSocket(issues[self.port][nbr])


class FakeHTTPHandler(urllib.request.HTTPHandler):
    connection = FakeHTTPConnection
    def http_open(self, req):
        print('opening', self.connection)
        return self.do_open(self.connection, req)


def process(*issue_nbrs):
    '''Run the specified tests, or all of them.'''

    if issue_nbrs:
        # Make sure the tests are ints.
        issue_nbrs = list(map(int, issue_nbrs))
    else:
        # If no tests were specified, run them all.
        issue_nbrs = list(issues.keys())

    assert all(i in issues for i in issue_nbrs)

    user = 'DOMAIN\\User'
    password = "Password"
    url = "http://www.example.org:%s/"

    # Set passwords for each of the "servers" to which we will be connecting.
    # Each distinct port on a server requires it's own set of credentials.
    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    for k in issue_nbrs:
        passman.add_password(None, url % k, user, password)

    # Create the NTLM authentication handler.
    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)

    # Create and install openers for both the NTLM Auth handler and
    # our fake HTTP handler.
    opener = urllib.request.build_opener(auth_NTLM, FakeHTTPHandler)
    urllib.request.install_opener(opener)

    # The following is a massive kludge; let me explain why it is needed.
    HTTPNtlmAuthHandler.http.client.HTTPConnection = FakeHTTPConnection
    # At the heart of the urllib2 module is the opener director. Whenever a
    # URL is opened, the director is responsible for locating the proper
    # handler for the protocol specified in the URL. Frequently, an existing
    # protocol handler will be subclassed and then added to the collection
    # maintained by the director. When urlopen is called, the specified
    # request is immediately handed off to the director's "open" method
    # which finds the correct handler and invokes the protocol-specific
    # XXX_open method. At least in the case of the HTTP protocols, if an
    # error occurs then the director is called again to find and invoke a
    # handler for the error; these handlers generally open a new connection
    # after adding headers to avoid the error going forward. Finally, it is
    # important to note that at the present time, the HTTP handlers in
    # urllib2 are built using a class that isn't prepared to deal with a
    # persistent connection, so they always add a "Connection: close" header
    # to the request.
    # 
    # Unfortunately, NTLM only certifies the current connection, meaning
    # that  a "Connection: keep-alive" header must be used to keep it open
    # throughout the authentication process. Furthermore, because the opener
    # director only provides a do_open method, there is no way to discover
    # the type of connection without also opening it. This means that the
    # HTTPNtlmAuthHandler cannot use the normal HTTPHandler and must
    # therefore must hardcode the HTTPConnection class. If a custom class is
    # required for whatever reason, the only way to cause it to be used is
    # to monkey-patch the code, as is done in the line above.

    for i in sorted(issue_nbrs):
        print('\nissue %d' % i)
        try:
            f = urllib.request.urlopen(url % i)
        except:
            traceback.print_exc()
        else:
            print(f.read())


# The following is adapted from Guido van van Rossum's suggestion.
# http://www.artima.com/weblogs/viewpost.jsp?thread=4829

import sys
import getopt

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

def main(argv=None):
    """Usage:  %s"""
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "h", ["help"])
        except getopt.error as msg:
             raise Usage(msg)
        if opts:
            raise Usage(main.__doc__)
        if len(args) > 0:
            raise Usage('takes no arguments (%d given)' % len(args))
        process(*args)
    except Usage as err:
        print(err.msg, file=sys.stderr)
        if err.msg is not main.__doc__:
            print("for help use --help", file=sys.stderr)
        return 2
main.__doc__ %= os.path.basename(sys.argv[0])

if __name__ == "__main__":
    sys.exit(main())
