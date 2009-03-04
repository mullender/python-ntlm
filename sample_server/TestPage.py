#!/usr/bin/env python

import operator, os, pickle, sys
from genshi.template import TemplateLoader
import cherrypy
import math

class TestPage(object):

    def __init__(self, loader):
	self.loader=loader

    @cherrypy.expose
    def index(self, **kwargs):
        tmpl = self.loader.load('testpage.html')
        ntlm_user, ntlm_domain = cherrypy.session.get("ntlm_auth", (None, None))
        return tmpl.generate(title='Test Page', body="This is a test page", ntlm_user=ntlm_user, ntlm_domain=ntlm_domain).render('html', doctype='html')
