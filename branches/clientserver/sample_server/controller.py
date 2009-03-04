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

def main():
    data = {} # We'll replace this later
    users = {"admin": "secretPassword",
             "editor": "otherPassword",
             "duncan": "password"}

    # Some global configuration; note that this could be moved into a
    # configuration file
    cherrypy.config.update({
        'tools.encode.on': True, 'tools.encode.encoding': 'utf-8',
        'tools.decode.on': True,
        'tools.trailing_slash.on': True,
        'tools.staticdir.root': os.path.abspath(os.path.dirname(__file__)),
    })

    cherrypy.quickstart(Root(data), '/', {
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static'
        },
        '/test_page': {'tools.ntlm_auth.on': True,
                       #'tools.ntlm_auth.realm' : 'Some site',
                       'tools.ntlm_auth.handler': HTTPServerAuthHandler(users = users, version=1)},
    })

if __name__ == '__main__':
    import sys
    if "--debug" in sys.argv:
        logging.getLogger().setLevel(logging.DEBUG)
    main()
