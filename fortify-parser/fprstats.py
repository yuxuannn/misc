import argparse
import logging

from fortify import ProjectFactory

parser = argparse.ArgumentParser("Print statistics from a Fortify FPR file")
parser.add_argument("-f", "--file", dest="fprfile", required=True,
                  help="generate stats for FPR", metavar="FPR")
parser.add_argument("-p", "--project_info", default=False,
                  action="store_true", dest="print_project_info",
                  help="print project and scan info")
parser.add_argument("-c", "--vuln_counts",
                  action="store_true", dest="print_vuln_counts", default=False,
                  help="print vulnerabilities as CSV output")
parser.add_argument("-s", "--vuln_summaries",
                  action="store_true", dest="print_vuln_summaries", default=False,
                  help="print vulnerability details as CSV output")
parser.add_argument("--high_priority_only",
                    action="store_true", dest="print_high_priority_only", default=False,
                    help="For vulnerability summaries: Filters only High Priority relevant issues, which includes Critical/High and excludes anything suppressed, removed, hidden, NAI")
parser.add_argument("-v", "--verbose", dest="verbose", required=False,
                    action="store_true", help="print verbose/debug output")

args = parser.parse_args()

# create console handler with a higher log level
logLevel = logging.DEBUG if args.verbose else logging.ERROR
#logging.basicConfig(level=logLevel,format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logLevel)
consoleLogger = logging.StreamHandler()
consoleLogger.setLevel(logLevel)
consoleLogger.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))

# add console logger to the root logger to cover all module loggers
rootLogger = logging.getLogger()
rootLogger.addHandler(consoleLogger)
rootLogger.setLevel(logLevel)

project = ProjectFactory.create_project(args.fprfile)

if args.print_project_info:
    project.print_project_info()

if args.print_vuln_counts:
    project.print_vuln_counts()

if args.print_vuln_summaries:
    project.print_vuln_summaries(args.print_high_priority_only)
