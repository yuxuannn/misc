# -*- coding: utf-8 -*-
'''
fortify.fvdl
~~~~~~~~~~~~

'''
from lxml.etree import ElementNamespaceClassLookup
from lxml.objectify import ElementMaker, ObjectifiedDataElement, \
    ObjectifyElementClassLookup
from lxml import objectify
from dateutil import tz
import arrow
import datetime
import dateutil.parser
import uuid
import re
import logging

logger = logging.getLogger(__name__)

# https://stackoverflow.com/a/6849299/630705
class lazyproperty(object):
    '''
    meant to be used for lazy evaluation of an object attribute.
    property should represent non-mutable data, as it replaces itself.
    '''

    def __init__(self,fget):
        self.fget = fget
        self.__name__ = fget.__name__

    def __get__(self,obj,cls):
        if obj is None:
            return None
        value = self.fget(obj)
        setattr(obj,self.__name__,value)
        return value

AuditParser = objectify.makeparser(ns_clean=True,
                                   remove_blank_text=True,
                                   resolve_entities=False,
                                   strip_cdata=False)

FilterTemplateParser = objectify.makeparser(ns_clean=True,
                                            remove_blank_text=True,
                                            resolve_entities=False,
                                            strip_cdata=False)

FVDLParser = objectify.makeparser(ns_clean=True,
                                  remove_blank_text=True,
                                  resolve_entities=False,
                                  strip_cdata=False,
                                  huge_tree=True)

AuditObjectifiedElementNamespaceClassLookup = ElementNamespaceClassLookup(
    ObjectifyElementClassLookup())

FVDLObjectifiedElementNamespaceClassLookup = ElementNamespaceClassLookup(
    ObjectifyElementClassLookup())

FilterTemplateObjectifiedElementNamespaceClassLookup = ElementNamespaceClassLookup(
    ObjectifyElementClassLookup())


class FortifyObjectifiedDataElement(ObjectifiedDataElement):
    def __repr__(self):
        return "<Element {0} at 0x{1:x}>".format(self.tag, id(self))


class FVDLElement(FortifyObjectifiedDataElement):
    def get_vulnerabilities(self):
        return self.Vulnerabilities.Vulnerability if hasattr(self.Vulnerabilities, 'Vulnerability') else []

class AuditElement(FortifyObjectifiedDataElement):

    issue_analysisInfo_lookup = {}

    # Build a lookup dictionary to speed up resolving the analysis lookups that otherwise take a considerable amount of time doing xpath
    def build_issue_analysis_lookup(self):
        for issue in self.IssueList.iter("{xmlns://www.fortify.com/schema/audit}Issue"):
            # The analysis tag ID depends on the project template but hard-coding
            # for now should be reasonably safe since this is the default tag ID for analysis issues.
            analysis = issue.find(
                './ns2:Tag[@id=\'87f2364f-dcd4-49e6-861d-f8d3f351686b\']/ns2:Value', namespaces={'ns2': 'xmlns://www.fortify.com/schema/audit'})
            analysisInfo = {}
            analysisInfo['analysis'] = analysis.text if analysis is not None else None
            analysisInfo['suppressed'] = True if 'suppressed' in issue.attrib and issue.attrib['suppressed'] == 'true' else False

            self.issue_analysisInfo_lookup[issue.attrib['instanceId']] = analysisInfo

    def get_issue_analysis(self, instanceId):
        return self.issue_analysisInfo_lookup[instanceId] if instanceId in self.issue_analysisInfo_lookup else None

class DateTimeElement(FortifyObjectifiedDataElement):
    def __repr__(self):
        return "<Element {0} at 0x{1:x}>".format(self.tag, id(self))

    @property
    def date(self):
        return self.datetime.date()

    @property
    def time(self):
        return self.datetime.time()

    @property
    def datetime(self):
        try:
            return arrow.get(str(self))
        except arrow.parser.ParserError:
            return arrow.get(dateutil.parser.parse(str(self)))


class TimeStampElement(FortifyObjectifiedDataElement):
    @property
    def date(self):
        return datetime.date(*list(map(int, self.get('date').split('-'))))

    @property
    def time(self):
        return datetime.time(*list(map(int, self.get('time').split(':'))))

    @property
    def datetime(self):
        return arrow.get(
            datetime.datetime.combine(self.date, self.time),
            tzinfo=tz.tzlocal())  # use local timezone


class UUIDElement(FortifyObjectifiedDataElement):
    @property
    def uuid(self):
        return uuid.UUID(str(self))

class RuleInfoElement(FortifyObjectifiedDataElement):

    rules = {}

    def _init(self):
        # build a quicker rule lookup to avoid lots of xpath queries
        for rule in self.iter("{xmlns://www.fortifysoftware.com/schema/fvdl}Rule"):
            self.rules[rule.attrib['id']] = rule

    def get_rule(self, ruleId):
        return self.rules[ruleId] if ruleId in self.rules else None

class RuleElement(FortifyObjectifiedDataElement):
    @property
    def id(self):
        return self.attrib['id']

    @lazyproperty
    def metadata(self):
        metadata = {}
        for group in self.MetaInfo.Group:
            metadata[group.attrib['name']] = group.text
        return metadata


class VulnerabilityElement(FortifyObjectifiedDataElement):
    @property
    def InstanceID(self):
        return self.InstanceInfo.InstanceID


class FilterQuery:
    # metadata_element is the value that the criteria applies to.  Criteria is applied to the value of the metadata element.
    def __init__(self, fpr, metadata_element=None, criteria=None, raw_querytext=None):
        self._metadata_element_shortcuts = []
        if raw_querytext is None:
            self._metadata_element = metadata_element
            self._criteria = criteria
        else:
            # split raw
            pieces = raw_querytext.split(':')
            self._metadata_element = re.sub('^\[|\]$', '', pieces[0])
            self._criteria = pieces[1]

            # Fortify actually uses shortcut names prefixed with
            # In filtertemplate.xml, it would specify [OWASP Top 10 2013], where that corresponds to a Name in
            # externalmetadata.xml. But in the actual audit.fvdl file, they use altcategoryOWASP2013 as the attribute
            # value for lookup.  This appears to be "altcategory" prefixing one of the Shortcut values from the
            # externalmetadata definitions: <Shortcut>OWASP2013</Shortcut>  So, we have to map one to the other for
            # lookups
            if fpr.ExternalMetadata is not None:
                metadata_element_shortcuts = fpr.ExternalMetadata.get_shortcuts_for_name(self._metadata_element)
                if len(metadata_element_shortcuts) > 0:
                    # we found shortcuts for this name, which means it's a metadata category name. Store all variations for
                    # matches in the future, prefixed with "altcategory" (but none have spaces, so excluding those)
                    self._metadata_element_shortcuts = []
                    for s in metadata_element_shortcuts:
                        if ' ' not in s:
                            self._metadata_element_shortcuts.append("altcategory" + s)

    def _evaluate_one(self, metadata_element, metadata):
        # This understands a limited set of Fortify's query language.  To really support this would take
        # more tests and reverse engineering perhaps and maybe a full blown syntax parser to do right
        is_filtered = False
        metadata_value = metadata.get(metadata_element, None)
        if metadata_value is not None:
            # parse the criteria and check the value against it.  Quick and dirty for now.  Supports substring match and
            # negated substring match
            negated = True if self._criteria.startswith('!') else False
            substring_to_find = self._criteria.replace('!', '')
            # contains = T, negated = F => T
            # contains = T, negated = T => F
            # contains = F, negated = F => F
            # contains = F, negated = T => T
            is_filtered = not ((metadata_value != 'None' and substring_to_find in metadata_value.lower()) and negated)

        return is_filtered

    def evaluate(self, metadata):
        is_filtered = False

        if len(self._metadata_element_shortcuts) > 0:
            # process metadata shortcuts, not the element itself
            for s in self._metadata_element_shortcuts:
                is_filtered = self._evaluate_one(s, metadata)
                if is_filtered:
                    break
        else:
            is_filtered = self._evaluate_one(self._metadata_element, metadata)

        return is_filtered


class FilterElement(FortifyObjectifiedDataElement):
    def get_filter_query(self, fpr):
        query_object = None
        # Not being able to have state is a really annoying limitation of lxml. We need to access externalmetadata here
        if self.action == 'hide':
            query_object = FilterQuery(raw_querytext=self.query.text, fpr=fpr)

        return query_object


class FilterTemplateElement(FortifyObjectifiedDataElement):
    # determines whether an issue is hidden or not
    def is_hidden(self, fpr, issue):

        is_hidden = False

        # skip if we've already done this to be idempotent
        if self.default_filterset is not None:

            # find all hide filter criteria and configure the object so they are available
            filter_queries = []
            hide_filters = self.default_filterset.xpath("./Filter[action = 'hide']")
            for f in hide_filters:
                filter_queries.append(f.get_filter_query(fpr))

            for q in filter_queries:
                is_hidden = q.evaluate(issue.metadata)
                if is_hidden:
                    break  # found a condition that applies (multiple separate conditions are ORed together)

        return is_hidden

    @lazyproperty
    def default_filterset(self):
        # find the active FilterSet and get any rules that hide things
        # TODO: could allow caller to specify which filterset to use to toggle views of data
        default_filter_set = self.find(".//FilterSet[@enabled='true']")
        if default_filter_set is None:
            logger.warn("No default filterset found!")

        return default_filter_set


AUDIT_NAMESPACE = AuditObjectifiedElementNamespaceClassLookup.get_namespace(
    'xmlns://www.fortify.com/schema/audit')

FVDL_NAMESPACE = FVDLObjectifiedElementNamespaceClassLookup.get_namespace(
    'xmlns://www.fortifysoftware.com/schema/fvdl')

FILTERTEMPLATE_NAMESPACE = FilterTemplateObjectifiedElementNamespaceClassLookup.get_namespace(None)

AUDIT_NAMESPACE['Audit'] = AuditElement
AUDIT_NAMESPACE['CreationDate'] = DateTimeElement
AUDIT_NAMESPACE['EditTime'] = DateTimeElement
AUDIT_NAMESPACE['RemoveScanDate'] = DateTimeElement
AUDIT_NAMESPACE['Timestamp'] = DateTimeElement
AUDIT_NAMESPACE['WriteDate'] = DateTimeElement

FVDL_NAMESPACE['BeginTS'] = TimeStampElement
FVDL_NAMESPACE['CreatedTS'] = TimeStampElement
FVDL_NAMESPACE['EndTS'] = TimeStampElement
FVDL_NAMESPACE['FVDL'] = FVDLElement
FVDL_NAMESPACE['FirstEventTimestamp'] = TimeStampElement
FVDL_NAMESPACE['ModifiedTS'] = TimeStampElement
FVDL_NAMESPACE['UUID'] = UUIDElement
FVDL_NAMESPACE['Vulnerability'] = VulnerabilityElement
FVDL_NAMESPACE['Rule'] = RuleElement
FVDL_NAMESPACE['RuleInfo'] = RuleInfoElement

FILTERTEMPLATE_NAMESPACE['FilterTemplate'] = FilterTemplateElement
FILTERTEMPLATE_NAMESPACE['Filter'] = FilterElement

AuditParser.set_element_class_lookup(
    AuditObjectifiedElementNamespaceClassLookup)

FVDLParser.set_element_class_lookup(
    FVDLObjectifiedElementNamespaceClassLookup)

FilterTemplateParser.set_element_class_lookup(
    FilterTemplateObjectifiedElementNamespaceClassLookup)

FVDL = ElementMaker(
    annotate=False,
    namespace='xmlns://www.fortifysoftware.com/schema/FVDL',
    nsmap={
        None: 'xmlns://www.fortifysoftware.com/schema/FVDL',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
    }
)

Audit = ElementMaker(
    annotate=False,
    namespace='',
    nsmap={
        None: 'xmlns://www.fortify.com/schema/AUDIT',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
    }
)


def parse(source, **kwargs):
    return objectify.parse(source, parser=FVDLParser, **kwargs)
