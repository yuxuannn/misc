# -*- coding: utf-8 -*-
'''
fortify.utils
~~~~~~~~~~~~~

'''
import os
from lxml import objectify
from zipfile import ZipFile
import logging

logger = logging.getLogger(__name__)

from .fvdl import AuditParser, FilterTemplateParser, FVDLParser
from .externalmetadata import ExternalMetadataParser


XML_PARSERS = {
    'audit.fvdl': FVDLParser,
    'audit.xml': AuditParser,
    'filtertemplate.xml': FilterTemplateParser,
    'ExternalMetadata/externalmetadata.xml': ExternalMetadataParser
}


def openfpr(fprfile):
    '''
    Read and parse important files from an FPR.

    :param fprfile: Path to the FPR file, or a file-like object.
    :returns: A dict of :class:`lxml.etree._ElementTree` objects.
    '''

    zfpr = fprfile

    if not isinstance(fprfile, ZipFile):
        zfpr = ZipFile(fprfile)

    pkg = {}

    for filename in (f for f in zfpr.namelist() if f in XML_PARSERS):
        parser = XML_PARSERS.get(filename)
        artifact = zfpr.open(filename)
        logger.debug("Parsing %s w/parser %r", filename, parser)
        # index by filename only, not folder
        filename = os.path.basename(filename)
        pkg[filename] = objectify.parse(artifact, parser=parser)

    logger.debug("Done parsing files from FPR")
    return pkg
