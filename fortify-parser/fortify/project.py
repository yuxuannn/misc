from __future__ import print_function

from . import FPR, Issue, RemovedIssue
import sys
import logging

logger = logging.getLogger(__name__)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# configures fortify project objects
class ProjectFactory:
    # creates a new project object by loading the FPR from fprpath and building necessary data structures
    def __init__(self):
        pass

    @staticmethod
    def create_project(fprpath):
        fpr = FPR(fprpath)

        project = Project(fpr)

        # find every vulnerability and model as an Issue object attached to the project
        logger.debug("Getting Vulnerabilities from FVDL")
        for vuln in fpr.FVDL.get_vulnerabilities():
            issue = Issue.from_vulnerability(vuln)

            rule = fpr.FVDL.EngineData.RuleInfo.get_rule(vuln.ClassInfo.ClassID)
            if rule is not None and hasattr(rule, 'metadata'):
                issue.add_metadata(rule.metadata)

            # now, we need to apply visibility rules from the filtertemplate, if one exists, for the
            # TODO: figure out if these two lines of code are useful - commented for now
            #if fpr.FilterTemplate is not None:
            #    issue.hidden = fpr.FilterTemplate.is_hidden(fpr, issue)

            project.add_or_update_issue(issue)

        # now, associate the analysis info with the issues we know about.
        # Only FPRs with audit information will have this to associate.
        logger.debug("Getting Issues for project and setting suppressed and analysis data.")
        issues = project.get_issues()
        logger.debug("Have to process %d issues." % len(issues))
        # build lookup
        fpr.Audit.build_issue_analysis_lookup()
        for issueid in issues:
            i = project.get_issue(issueid)
            analysisInfo = fpr.Audit.get_issue_analysis(issueid)
            if analysisInfo is not None:
                # set suppressed status
                i.suppressed = analysisInfo['suppressed']
                if analysisInfo['analysis'] is not None:
                    i.analysis = analysisInfo['analysis']

            project.add_or_update_issue(i)  # add it back in to replace the previous one

        # now, add information about removed issues
        logger.debug("Getting information about removed issues")
        if hasattr(fpr.Audit, 'IssueList') and hasattr(fpr.Audit.IssueList, 'RemovedIssue'):
            for removed in fpr.Audit.IssueList.RemovedIssue:
                ri = RemovedIssue.from_auditxml(removed)
                project.add_or_update_issue(ri)

        removedissues = [i for i in list(issues.values()) if i.removed]
        suppressedissues = [i for i in list(issues.values()) if i.suppressed]
        hiddenissues = [i for i in list(issues.values()) if i.hidden]
        naiissues = [i for i in list(issues.values()) if i.is_NAI()]
        eprint("Got [%d] issues, [%d] hidden, [%d] NAI, [%d] Suppressed, [%d] Removed" % (len(issues), len(hiddenissues), len(naiissues), len(suppressedissues), len(removedissues)))

        return project  # A fortify project, containing one or more issues, with metadata


class Project:
    def __init__(self, fpr):
        self._fpr = fpr
        self._issues = {}

        # set project properties
        if hasattr(fpr.Audit.ProjectInfo, 'Name'):
            self.ProjectName=fpr.Audit.ProjectInfo.Name
        else:
            self.ProjectName=None

        if hasattr(fpr.Audit.ProjectInfo, 'ProjectVersionId'):
            self.ProjectVersionId=fpr.Audit.ProjectInfo.ProjectVersionId
        else:
            self.ProjectVersionId=None

        for loc in fpr.FVDL.Build.LOC:
            if loc.attrib['type'] == 'Fortify':
                self.ScannedELOC=loc.text
            elif loc.attrib['type'] == 'Line Count':
                self.ScannedLOC=loc.text

    def add_or_update_issue(self, issue):
        if issue.id in self._issues:
            # remove first and decrement counts, if change in severity
            current = self._issues[issue.id]
            if issue != current:
                # unless this is a new object, nothing to do
                del self._issues[issue.id]

        # add the issue to the list, if necessary
        self._issues[issue.id] = issue

    def get_issues(self):
        return self._issues

    def get_issue(self, id):
        return self._issues[id]

    def print_project_info(self):
        # TODO: print an overview of the project information (name, etc.) and scan information
        return

    def print_vuln_counts(self):
        vuln_counts = {'Critical': 0,
                        'High': 0,
                        'Medium': 0,
                        'Low': 0,
                        }
        for i in list(self._issues.values()):
            # exclude hidden, NAI and suppressed (TODO: could be configurable)
            if not (i.hidden or i.is_NAI() or i.suppressed):
                if i.risk is None:
                    logger.warn("Risk calculation error for issue [%s]" % i.id)
                else:
                    vuln_counts[i.risk] += 1

        print("Critical, High, Medium, Low")
        print("%d, %d, %d, %d" % (vuln_counts['Critical'], vuln_counts['High'], vuln_counts['Medium'], vuln_counts['Low']))

    # def print_vuln_summaries(self, open_high_priority):
    #     # TODO: enable sorting by severity and file_line by default.
    #     print("file_line,path,id,kingdom,type_subtype,severity,nai,filtered,suppressed,removed,analysis")
    #     for i in self._issues.values():
    #         if not open_high_priority or i.is_open_high_priority:
    #             print("%s:%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % \
    #                   (i.metadata['shortfile'], i.metadata['line'], i.metadata['file'], i.id, i.kingdom, i.category, i.risk, i.is_NAI(), "H" if i.hidden else "V", i.suppressed, i.removed, i.analysis))

    def print_vuln_summaries(self, _):
        # Prints information useful for filling up the Affected Module segment of an issue writeup
        # The original 'open_high_priority' parameter is not used, hence replaced with a _
        print("file_line,type_subtype")
        for i in self._issues.values():
            try: 
                if not i.suppressed:
                    file_line = "{}:{}".format(i.metadata['file'],i.metadata['line'])
                    type_subtype = i.category
                    print("{},{}".format(file_line, type_subtype))
            except:
                print("There seems to be an error with this particular issue: {}".format(i.kingdom))

    def get_fpr(self):
        return self._fpr
