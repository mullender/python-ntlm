#!/usr/bin/env python

import operator, os, pickle, sys
import cherrypy
import NTLMAuth
from ntlm.HTTPServerAuthHandler import HTTPServerAuthHandler
from genshi.template import TemplateLoader
from TestPage import TestPage
import logging

loader = TemplateLoader(
    os.path.join(os.path.dirname(__file__), 'templates'),
    auto_reload=True
)

class Root(object):

    test_page = TestPage(loader)

    def __init__(self, data):
        self.data = data

    @cherrypy.expose
    def index(self, **kwargs):
        tmpl = loader.load('index.html')
        return tmpl.generate(title='Index Page', body="This is the index page").render('html', doctype='html')

def main(options):
    data = {} # We'll replace this later
    users = {"admin": "secretPassword",
             "editor": "otherPassword",
             "duncan": "password"}

    # Some global configuration; note that this could be moved into a
    # configuration file
    cherrypy.config.update({
        'tools.decode.on': True,
        'tools.encode.on': True,
        'tools.encode.encoding': 'utf-8',
        'tools.staticdir.root': os.path.abspath(os.path.dirname(__file__)),
        'tools.trailing_slash.on': True,
    })
    if options.host:
        cherrypy.config["server.socket_host"] = options.host

    cherrypy.quickstart(Root(data), '/', {
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static'
        },
        '/test_page': {'tools.ntlm_auth.on': True,
                       #'tools.ntlm_auth.realm' : 'Some site',
                       'tools.ntlm_auth.handler': HTTPServerAuthHandler(users = users, version=options.ntlm_version)},
    })

if __name__ == '__main__':
    import sys
    import optparse
    optparser = optparse.OptionParser()
    optparser.add_option("", "--loglevel", type="string", dest="loglevel", default="warn",
                    help="Logging level. Options are: notset, debug, info, warn, error, fatal. [warn]")
    optparser.add_option("-1", "--version1", action="store_const", dest="ntlm_version", default=1, const=1,
                    help="Require NTLM Version 1")
    optparser.add_option("-2", "--version2", action="store_const", dest="ntlm_version", const=2,
                    help="Require NTLM Version 2")
    optparser.add_option("", "--host", type="string", dest="host", default=None,
                    help="Listen on the given host name/IP address")
    options, arguments = optparser.parse_args()
    if arguments:
        optparser.error("Unexpected arguments %s" % (" ".join(arguments)))
    try:
        loglevel = getattr(logging, options.loglevel.upper())
        logging.getLogger().setLevel(loglevel)
    except AttributeError:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.error("Unknown logging level '%s', switching to DEBUG loglevel." % options.loglevel)
    main(options)

