# -*- coding: utf-8 -*-
'''
fortify.fpr
~~~~~~~~~~~

'''
from .utils import openfpr


class FPR(object):

    cache = {}

    def __init__(self, project, **kwargs):
        if isinstance(project, str):
            self._project = project = openfpr(project)
        elif isinstance(project, dict):
            self._project = project
        else:
            raise TypeError

        self.FVDL = project['audit.fvdl'].getroot()
        self.cache[self.FVDL] = list(self.FVDL.iter())
        self.Audit = project['audit.xml'].getroot()
        self.cache[self.Audit] = list(self.Audit.iter())

        self.FilterTemplate=None

        if 'filtertemplate.xml' in project:
            self.FilterTemplate = project['filtertemplate.xml'].getroot()
            #self.cache[self.FilterTemplate] = list(self.FilterTemplate.iter())

        self.ExternalMetadata=None
        if 'externalmetadata.xml' in project:
            self.ExternalMetadata = project['externalmetadata.xml'].getroot()
            #self.cache[self.ExternalMetadata] = list(self.ExternalMetadata.iter())
