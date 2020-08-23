#!/usr/bin/python3

import csv
from jira import JIRA

# Script : to parse csv findings from ScoutSuite results to JIRA via REST API
# To be executed after aws-scans.py
# If existing issue exists, and is not in Review / Invoice / Done, it will be returned to Plan status
# If existing issue is in Review / Invoice / Done, new issue will be created instead (due to transitioning limitations)

user='yuxuan@pragmastrategy.com'
apikey='apikey'
server='https://pragmastrategy.atlassian.net'

options = {
'server': server
}

jira = JIRA(options, basic_auth=(user,apikey) )
with open('scoutresults.csv', newline='') as datafile:
    DataCaptured = csv.reader(datafile, delimiter=',', skipinitialspace=True) 
    Finding, Rational, Full= [], [], []

    for row in DataCaptured:
        Full.append(row)
        if row[2] not in Finding:
            Finding.append(row[2])
            Rational.append(row[5])
    del Finding[0]

    #print (Finding)
    #print ('---')

    i=1     

    for f in Finding:
        Details = []
        #print(f)
        #print('~~~')
        for row in Full:
            #print(row[2])
            #print('---')
            if row[2] == f:
                Details.append(row[7])
        #print (Details)
        #print ('---')  

        #if ticket exists
        jql = "issuetype in (standardIssueTypes(), subTaskIssueTypes()) AND project = PD AND status != Done AND status != Invoice AND status != Review order by created DESC"

        block_size = 100
        block_num = 0
        ticketExists = False

        while True:
            start_idx = block_num * block_size
            if block_num == 0:
                issues = jira.search_issues(jql, start_idx, block_size)

            else:
                more_issue = jira.search_issues(jql, start_idx, block_size)

                if len(more_issue)>0:
                    for x in more_issue:
                        issues.append(x)

                else:
                    break

            if len(issues) == 0:
                break

            block_num += 1

        for issue in issues:
            if issue.fields.summary == f:
                #print('- %s: %s' % (issue.key, issue.fields.summary))
                existKey = issue.key
                jira.add_comment(issue.key, ''.join(Details))

                #transition issue to status 'plan'
                jira.transition_issue(issue, "91")

                ticketExists = True
             

        #if no ticket exists
        if not ticketExists:
            issue_data = {
                "project" : "PD",
                "summary": f,
                "description": Rational[i],
                "issuetype": {'id': "10002"}
            }

            created_issue = jira.create_issue(fields=issue_data)
            jira.add_comment(created_issue.key, ''.join(Details))  

        #print(f+' : '+Rational[i])
        #print(Details)
        #print('---')
    
        i+=1
        del Details[:] 
