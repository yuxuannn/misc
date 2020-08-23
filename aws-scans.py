#!/usr/bin/python3
import json as j
import csv
import sys

def process_scout(jsonfile,account,duplicate=True):
    rowslist = []
    if duplicate:
        with open(jsonfile) as scoot_result:
            r = j.load(scoot_result)
            for s in r['services']:
                for f in r['services'][s]['findings']:
                    rowslist = rowslist + [[account,s,f,
                                        r['services'][s]['findings'][f]['description'],
                                        r['services'][s]['findings'][f]['level'],
                                        r['services'][s]['findings'][f]['rationale'].replace('<b>Description:</b><br><br>',''),
                                        r['services'][s]['findings'][f]['flagged_items'],i] 
                                       for i in r['services'][s]['findings'][f]['items']]
    else:
        rows = []
        finding = []
        for s in r['services']:
            for f in r['services'][s]['findings']:
                finding =[s,
                     f,
                     r['services'][s]['findings'][f]['description'],
                     r['services'][s]['findings'][f]['level'],
                     r['services'][s]['findings'][f]['rationale'].replace('<b>Description:</b><br><br>',''),
                     r['services'][s]['findings'][f]['flagged_items']]
            
            for i,v in enumerate(r['services'][s]['findings'][f]['items']):
                if i == 0:
                    rows.append(finding + [v])
                else:
                    rows.append(['','','','','','',v])
    
    return rowslist


def write_scout(listofrows):
    # csv columns 
    fields = ['Account','Service', 'Finding', 'Description', 'Risk', 'Rational','Count','Details']
    # name of csv file 
    filename = "scoutresults.csv"

    # writing to csv file 
    with open(filename, 'w') as csvfile: 
        # creating a csv writer object 
        csvwriter = csv.writer(csvfile) 
      
        # writing the fields 
        csvwriter.writerow(fields) 
      
        # writing the data rows
        #for rows in rowslist:
        csvwriter.writerows(listofrows)

results = process_scout(str(sys.argv[1]),str(sys.argv[2]))
#results = process_scout("/root/Downloads/QuantbetQuant/scoutsuite-results/scoutsuite_results_aws-QuantbetQuant.js","QuantbetQuant")
write_scout(results)

# with open("data/bambu_scanresult/bamburoot/scoutsuite-results/scoutsuite_results_aws-bamburoot_copy.js") as scoot_result:
#     r = j.load(scoot_result)
#     rows = []
#     finding = []
#     for s in r['services']:
#         for f in r['services'][s]['findings']:
#             finding =[s,
#                      f,
#                      r['services'][s]['findings'][f]['description'],
#                      r['services'][s]['findings'][f]['level'],
#                      r['services'][s]['findings'][f]['rationale'].replace('<b>Description:</b><br><br>',''),
#                      r['services'][s]['findings'][f]['flagged_items']]
            
#             for i,v in enumerate(r['services'][s]['findings'][f]['items']):
#                 if i == 0:
#                     rows.append(finding + [v])
#                 else:
#                     rows.append(['','','','','','',v])
