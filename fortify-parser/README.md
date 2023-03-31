Setup
=====
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Usage
=====
`python fprstats.py -f {file.fpr} -s > output.csv`

Open `output.csv` in Excel and sort it manually.

Data > Sort > "My data has headers" > Sort by `type_subtype` first, then `file_line`

Example
=======
```
$ python fprstats.py -f sample-java-project.fpr -s 
Got [5] issues, [0] hidden, [0] NAI, [2] Suppressed, [0] Removed
file_line,type_subtype
src/sample/java/project/SampleJavaProject.java:41,J2EE Bad Practices: Leftover Debug Code
src/sample/java/project/SampleJavaProject.java:53,J2EE Bad Practices: JVM Termination
pom.xml:1,Build Misconfiguration: External Maven Dependency Repository
```

2 issues were marked as Suppressed and they do not show up in the CSV output. 

Workflow
========
Run a scan using Fortify SCA. While going through the results in Audit Workbench, suppress the issues that are determined to be False Positives.

After that, run the resulting `file.fpr` through the script and it will give you the affected files and their corresponding line numbers in the CSV output. The neat thing about this is that suppressed issues do not show up in the CSV, so the output only contains lines that you need to copy to the report.

**Sample output:**
```
$ cat js-edited.csv
file_line,type_subtype
temp/webapp/node_modules/node-gyp/gyp/pylib/gyp/input.py:521,Poor Logging Practice: Use of a System Output Stream
temp/webapp/node_modules/node-gyp/gyp/pylib/gyp/MSVSVersion.py:205,Poor Error Handling: Empty Catch Block
temp/webapp/node_modules/stompjs/lib/stomp-node.js:36,Insecure Transport
temp/webapp/build/static/js/7.e0f137f9.chunk.js:2,Insecure Randomness
temp/webapp/node_modules/sockjs-client/lib/utils/random.js:21,Insecure Randomness
temp/webapp/build/static/js/13.99011ca6.chunk.js:2,Weak Cryptographic Hash

[TRUNCATED]

```

Personally, I like to sort the CSV data in Excel first, which makes it easier for me to copy and paste.

Notes
=====
I have customized this tool according to my needs while writing the report, as well as fixed some bugs present in the original tool. 

If you would like to change how the output is presented, do take a look at the `print_vuln_summaries` function in `project.py`.

The original content in the README is reproduced below. It contains useful information regarding this tool.

Overview
========

This is a utility to parse Fortify FPR files and generate meaningful output that can be used in automated processes or reports.

The summary statistics can print out just the vulnerability counts so you can do things like flag apps that have > 0 critical or high vulnerabilities.

The vulnerability summaries output can be used to send to developers who may not have HPE Fortify Auditworkbench or access to the Fortify SSC UI (e.g. vendors/contractors).  It could also be used as input to a script to auto-assign vulnerabilities to dev teams.  Or it could just let you pivot around the vulnerability statistics in an application.

Fortify SSC UI has a REST interface now that may be useful instead of this tool, although it may be far slower for large projects than just parsing the FPR file.  This utility also works offline if you have copies of FPR files already downloaded.

About FPR Files
-----

Fortify FPR files are just zip archives with various XML files inside.  The parsing of the FPR file for this utility was mostly reverse-engineering and comparing to the Fortify results.  I was able to get Fortify tech support to provide some of the calculations for the derived values that are used to calculate the criticality (aka Fortify Priority Order) though.

There is a secret keyboard combination in Auditworkbench *COMMAND + OPTION + SHIFT + F* that provides a dump of the known attributes of a vulnerability instance that you can use for filters.

Limitations
----

This utility currently implements very limited support for Fortify filtering syntax so won't generate counts for all but a couple of filter scenarios.  Would be nice to add more use cases at some point.  The FilterQuery class implements evaluation logic of the query and supports only:

* Substring match
* Negated substring match

e.g. "Any vulnerability instance with a category containing the word Path"

```
category:Path
```

or "Any vulnerability instance that is not marked as Exploitable"

```
analysis:!Exploitable
```

This utility also doesn't support custom filter sets that can vastly change the vulnerability visibility and classifications.  It just uses the Default filter set in the FPR.  Would not be difficult to expose the ability to specify a non-default filter set, perhaps even by the string name.

Tips
----

Watch out if you are using this to process FPR files generated directly from a scan before they have been uploaded to Fortify SSC.  The vulnerability counts you see will not likely match up to what is on the Fortify SSC server due to:

* Not having the same Project Template applied to the generated FPR as is applied and enforced on the Fortify SSC server (this can change visibility/filtering of vulnerabilities, reclassify vulnerabilities to different folders, different filter sets, etc. that all can result in different vulnerability counts)
* Not having any of the auditing information available or suppression information that could change the vulnerability counts.

Installation
============

Install to a user directory on OSX:
```bash
python setup.py install --user --prefix=
```

Using the command-line utility
================

Usage help
---------

```
usage: Print statistics from a Fortify FPR file [-h] -f FPR [-p] [-c] [-s]
                                                [--high_priority_only] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -f FPR, --file FPR    generate stats for FPR
  -p, --project_info    print project and scan info
  -c, --vuln_counts     print vulnerabilities as CSV output
  -s, --vuln_summaries  print vulnerability details as CSV output
  --high_priority_only  For vulnerability summaries: Filters only High
                        Priority relevant issues, which includes Critical/High
                        and excludes anything suppressed, removed, hidden, NAI
  -v, --verbose         print verbose/debug output
```

Print out vulnerability counts for an FPR
------

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr 
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
```

Print out vulnerability counts as CSV (machine-readable) format
------

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr -c
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
Critical, High, Medium, Low
0, 15, 0, 93
```

Print a report containing vulnerability summaries as CSV format
-----

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr -s
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
file_line,path,id,kingdom,type_subtype,severity,nai,filtered,suppressed,removed
MyService.java:100,src/main/java/com/example/www/myapp/services/MyService.java,1BE7DEE63734F7EC117948FACE57A977,Errors,Poor Error Handling: Overly Broad Throws,Low,False,V,False,False
....
```

You can redirect the CSV outputs to a file:

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr -c > /tmp/MyApp.csv
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
```

MyApp.csv contains:

```
$ cat /tmp/MyApp.csv
Critical, High, Medium, Low
0, 15, 0, 93
```

Getting verbose log output to stderr
-----

```bash
$ fprstats.py --high_priority_only -s -f ~/Downloads/MyApp.fpr -v > ~/Downloads/expweb-high-priority.csv 
```

Would generate output like:

```
2016-10-24 14:58:08,689 fortify.utils DEBUG    Parsing audit.xml w/parser <lxml.etree.XMLParser object at 0x10f9ff370>
2016-10-24 14:58:08,941 fortify.utils DEBUG    Parsing filtertemplate.xml w/parser <lxml.etree.XMLParser object at 0x10f9ff4b0>
2016-10-24 14:58:08,942 fortify.utils DEBUG    Parsing audit.fvdl w/parser <lxml.etree.XMLParser object at 0x10f9ff550>
2016-10-24 14:58:27,547 fortify.utils DEBUG    Done parsing files from FPR
2016-10-24 14:58:48,505 fortify.project DEBUG    Getting Vulnerabilities from FVDL
2016-10-24 14:59:49,942 fortify.project DEBUG    Getting Issues for project and setting suppressed and analysis data.
2016-10-24 14:59:49,942 fortify.project DEBUG    Have to process 12345 issues.
2016-10-24 14:59:50,729 fortify.project DEBUG    Getting information about removed issues
Got [12345] issues, [1000] hidden, [10286] NAI, [59] Suppressed, [1000] Removed
2016-10-24 14:59:59,792 fortify.issue WARNING  Issue ID [B8F6FFD4A133A695B0B3F5B229C6A070] Missing Impact: Password Management : Null Password
```

Using the module in another python application
================
```python
from fortify import ProjectFactory

project = ProjectFactory.create_project("some/path/to/file.fpr")

# Now, print vulnerability summaries, etc.
project.print_vuln_counts()
```
