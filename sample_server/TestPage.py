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
        tmpl = self.loader.load('index.html')
        return tmpl.generate(title='Test Page', body="This is a test page").render('html', doctype='html')
