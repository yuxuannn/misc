import os
from decimal import *
import logging

logger = logging.getLogger(__name__)

# object representing a Fortify issue
class Issue:
    def __init__(self, iid, ruleid, kingdom, type, subtype):
        self.metadata = {}
        self.id = iid  # instance ID
        self.ruleid = ruleid
        self.kingdom = kingdom
        self.type = type
        self.subtype = subtype

    # Factory method to create an instance from a vulnerability XML object directly
    @classmethod
    def from_vulnerability(cls, vulnerability):
        instance = cls(vulnerability.InstanceID, vulnerability.ClassInfo.ClassID,
                       vulnerability.ClassInfo.Kingdom, vulnerability.ClassInfo.Type,
                       vulnerability.ClassInfo.Subtype if hasattr(vulnerability.ClassInfo, 'Subtype') else None)
        instance._build_metadata(vulnerability)
        return instance

    # augments the metadata dictionary with additional metadata, such as rule metadata
    def add_metadata(self, rulemetadata):
        self.metadata.update(rulemetadata)
        # some of these have different case or strings in the XML so add equivalent versions that
        # Fortify uses for filters
        if 'Accuracy' in self.metadata:
            self.metadata['accuracy'] = Decimal(self.metadata['Accuracy'])
        if 'Impact' in self.metadata:
            self.metadata['impact'] = Decimal(self.metadata['Impact'])
        # Fortify only uses this it seems if the instance probability is not set
        if 'Probability' in self.metadata and 'probability' not in self.metadata:
            self.metadata['probability'] = Decimal(self.metadata['Probability'])
        if 'RemediationEffort' in self.metadata:
            self.metadata['remediation effort'] = Decimal(self.metadata['RemediationEffort'])

    @property
    def category(self):
        # returns a combination of type and subtype, or just type if that's all we have
        return self.type + ': ' + self.subtype if self.subtype is not None else self.type

    @property
    def analysis(self):
        return self.metadata['analysis'] if 'analysis' in self.metadata else None

    @analysis.setter
    def analysis(self, analysis):
        self.metadata['analysis'] = analysis

    @property
    def hidden(self):
        # TODO: determine who should own issue visibility, especially since that can change by filters
        return self.removed

    @property
    def removed(self):
        return 'analyzer' in self.metadata and self.metadata['analyzer'] == 'RemovedIssue'

    @property
    def suppressed(self):
        return self.metadata['suppressed'] == 'true' if 'suppressed' in self.metadata else False

    @suppressed.setter
    def suppressed(self, suppressed):
        self.metadata['suppressed'] = str(suppressed).lower()

    # generate the metadata dictionary for the issue.  Here is an example:
    def _build_metadata(self, vulnerability):
        # add vulnerability metadata
        # TODO: add more
        self.metadata['severity'] = Decimal(vulnerability.InstanceInfo.InstanceSeverity.pyval)
        self.metadata['confidence'] = Decimal(vulnerability.InstanceInfo.Confidence.pyval)
        if hasattr(vulnerability.InstanceInfo, 'MetaInfo'):
            # this probability takes precedence over rule probability
            prob = vulnerability.InstanceInfo.MetaInfo.find("./x:Group[@name='Probability']", namespaces={
                'x': 'xmlns://www.fortifysoftware.com/schema/fvdl'})
            if prob is not None:
                self.metadata['probability'] = Decimal(prob.pyval)

        # /f:FVDL/f:Vulnerabilities/f:Vulnerability[2]/f:AnalysisInfo/f:Unified/f:Context
        if hasattr(vulnerability.AnalysisInfo.Unified, "Trace") and hasattr(
                vulnerability.AnalysisInfo.Unified.Trace.Primary.Entry, "Node"):
            # This is more consistent with what Fortify shows, if available
            child = vulnerability.AnalysisInfo.Unified.Trace.Primary.Entry.Node.SourceLocation
            self.metadata['file'] = child.attrib['path']
            if 'shortfile' not in self.metadata:
                self.metadata['shortfile'] = os.path.basename(child.attrib['path'])
            if 'line' not in self.metadata:
                self.metadata['line'] = child.attrib['line']
        elif hasattr(vulnerability.AnalysisInfo.Unified, 'ReplacementDefinitions'):
            child = vulnerability.AnalysisInfo.Unified.ReplacementDefinitions
            for thisdef in child.Def:
                if thisdef.attrib['key'] == 'PrimaryLocation.file':
                    self.metadata['shortfile'] = thisdef.attrib['value']
                elif thisdef.attrib['key'] == 'PrimaryLocation.line':
                    self.metadata['line'] = thisdef.attrib['value']

        if hasattr(vulnerability.AnalysisInfo.Unified.Context, 'FunctionDeclarationSourceLocation'):
            child = vulnerability.AnalysisInfo.Unified.Context.FunctionDeclarationSourceLocation
            self.metadata['file'] = child.attrib['path']
            if 'shortfile' not in self.metadata:
                self.metadata['shortfile'] = os.path.basename(child.attrib['path'])
            if 'line' not in self.metadata:
                self.metadata['line'] = child.attrib['line']

        self.metadata['category'] = self.category
        self.metadata['type'] = self.type
        self.metadata['subtype'] = self.subtype

        if hasattr(vulnerability.AnalysisInfo.Unified.Context, 'Function'):
            child = vulnerability.AnalysisInfo.Unified.Context.Function
            # namespace not always populated for some reason
            self.metadata['package'] = child.attrib['namespace'] if 'namespace' in child.attrib else None
            self.metadata['class'] = child.attrib['enclosingClass'] if 'enclosingClass' in child.attrib else None
        elif hasattr(vulnerability.AnalysisInfo.Unified.Context, 'ClassIdent'):
            child = vulnerability.AnalysisInfo.Unified.Context.ClassIdent
            self.metadata['package'] = child.attrib['namespace'] if 'namespace' in child.attrib else None
            self.metadata['class'] = None
        else:
            # Fortify builds a package name even in this case. Not sure what data it uses from FVDL.
            self.metadata['package'] = None
            self.metadata['class'] = None

    def _likelihood(self):
        # This comes from Fortify support documentation
        # Likelihood = (Accuracy x Confidence x Probability) / 25
        likelihood = (self.metadata['accuracy'] * self.metadata['confidence'] * self.metadata['probability']) / 25
        return round(likelihood, 1)

    def is_NAI(self):
        return self.analysis == 'Not an Issue'

    @property
    def risk(self):
        # This calculates Fortify Priority Order, which actually uses other metadata to place vulnerabilities
        # into 1 of 4 quadrants of a grid based on thresholds as follows (from Fortify support documentation):
        # - 'Critical' if Impact >=2.5 && Likelihood >= 2.5.
        # - 'High' If Impact >=2.5 && Likelihood < 2.5.
        # - 'Medium' If Impact < 2.5 && Likelihood >= 2.5.
        # - 'Low' if impact < 2.5 && likelihood < 2.5.
        criticality = None

        if 'impact' in self.metadata:
            impact = self.metadata['impact']
            likelihood = self._likelihood()

            if impact >= 2.5 and likelihood >= 2.5:
                # print "Rule ID [%s] Critical:  impact [%d], likelihood [%d], accuracy [%d], confidence [%d], probability[%d]" %
                #    (self.id, impact, self._likelihood(), self.metadata['accuracy'], self.metadata['confidence'], self.metadata['probability'])
                criticality = 'Critical'
            elif impact >= 2.5 > likelihood:
                criticality = 'High'
            elif impact < 2.5 <= likelihood:
                criticality = 'Medium'
            elif impact < 2.5 and likelihood < 2.5:
                criticality = 'Low'
        else:
            logger.warn("Issue ID [%s] Missing Impact: %s : %s" % (self.id, self.type, self.subtype))

        return criticality

    @property
    def is_open_high_priority(self):
        # encapsulates the logic of whether a finding is open and high priority
        risk = self.risk
        pci_relevant = (risk == 'Critical' or risk == 'High') \
                       and not self.is_NAI() \
                       and not self.removed \
                       and not self.suppressed \
                       and not self.hidden
        return pci_relevant


class RemovedIssue(Issue):
    @classmethod
    def from_auditxml(cls, removed):
        type_subtype = cls._split_type_subtype(removed.Category)
        instance = cls(removed.attrib['instanceId'], None,
                       'Unknown - Custom Issue', type_subtype[0],
                       type_subtype[1] if len(type_subtype) == 2 else None)
        instance._build_removed_metadata(removed)
        return instance

    @classmethod
    def _split_type_subtype(cls, category):
        # removed issues have a single field with combined type/subtype (or not) so this splits those back out
        pieces = category.text.split(':')
        return pieces

    def _build_removed_metadata(self, removed):
        self.metadata['analyzer'] = 'RemovedIssue'
        self.metadata['category'] = self.category
        self.metadata['type'] = self.type
        self.metadata['subtype'] = self.subtype

        self.metadata['file'] = removed.File.text
        self.metadata['shortfile'] = os.path.basename(removed.File.text)
        self.metadata['line'] = removed.Line
        self.metadata['confidence'] = Decimal(removed.Confidence.pyval)
        self.metadata['severity'] = Decimal(removed.Severity.pyval)
        self.metadata['probability'] = Decimal(removed.Probability.pyval)
        self.metadata['accuracy'] = Decimal(removed.Accuracy.pyval)
        self.metadata['impact'] = Decimal(removed.Impact.pyval)
