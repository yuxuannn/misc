import sys, os, csv, re, ipaddress, socket
from lxml import etree as ET
from lxml.html import fromstring, tostring
# pip3 install xlrd to read_excel
#from pptx.dml.color import RGBColor
# pip3 install python-pptx not pip3 install pptx
from cvss import CVSS2, CVSS3
import pandas as pd
import numpy as np
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', -1)
import time
import html

# Create a 'ConsolidatedResultsByTitle-<folder>.xlsx' in same folder as inputFile
def mergeconsolidatebytitle(inputFile):
    (baseFolder, basename)=os.path.split(inputFile)
    print('baseFolder: ', baseFolder) # G:\scanners
    print('basename: ', basename) # ConsolidatedResults.xlsx
    (baseFolder2, foldername)=os.path.split(baseFolder)
    print('baseFolder2: ', baseFolder2) # G:\
    print('foldername: ', foldername) # scanners
    (filename, fileext)=os.path.splitext(basename)
    print('filename: ', filename) # ConsolidatedResults
    print('fileext: ', fileext) # .xlsx
    #baseFolder=path2
    timestr = time.strftime("%Y%m%d-%H%M%S")
    outputFile1=os.path.join(baseFolder, 'ConsolidatedResultsByTitle-'+foldername+basename+'_'+timestr+'.xlsx')
    print('outputFile1: ',outputFile1)
    #outputFile1=inputFile
    writer2=pd.ExcelWriter(outputFile1)

    # Read from INput File
    #xl=pd.ExcelFile(inputFile,engine='openpyxl')
    #dfvulns = xl.parse('Raw')
    dfvulns = pd.read_csv(inputFile)

    
    dfvulns.to_excel(writer2, sheet_name='Raw')



    # Cannot include Exploits here because it is inconsistent and may result in duplidate output
    outputcols=['Rule Title','Description','Implication','Recommendation','References','Account',
    'Severity','Status','Region','Resource Type','Resource','Resource Name','Account GID','Notes',
    'Scoring']


    dfvulnsbytitle=dfvulns[outputcols]

    # Reading from excel will have NA for blank 'Test Output' which will cause error
    # TypeError: '<' not supported between instances of 'str' and 'float'
    dfvulnsbytitle=dfvulnsbytitle.fillna('')
    # Remove [New] from issue titles
    dfvulnsbytitle['Rule Title']=dfvulnsbytitle['Rule Title'].map(lambda x: x.split('[New] ')[-1])

    groupedbycols = ['Rule Title','Description','Implication','Recommendation','References','Account','Severity','Status','Scoring','Resource Type','Region']
    tocombine = []
    tocombinecrlf = ['Region','Resource','Resource Name','Notes']
    tocombinecomma = []
    tocombinemax = []        
    dfvulnsbytitle=dfvulnsbytitle.sort_values(by=groupedbycols).reset_index(drop=True)
    dfvulnsbytitle[tocombinecrlf]=pd.DataFrame(dfvulnsbytitle.groupby(groupedbycols)[tocombinecrlf].transform(lambda x: '\n'.join(sorted(x.unique()))))

    #dfvulnsbytitle[tocombinecomma]=pd.DataFrame(dfvulnsbytitle.groupby(groupedbycols)[tocombinecomma].transform(lambda x: ','.join(sorted(x.unique()))))
    dfvulnsbytitle['Resource']=dfvulnsbytitle['Region']+'\n'+dfvulnsbytitle['Resource']
    dfvulnsbytitle['Resource Name']=dfvulnsbytitle['Region']+'\n'+dfvulnsbytitle['Resource Name']
    dfvulnsbytitle['Notes']=dfvulnsbytitle['Region']+'\n'+dfvulnsbytitle['Notes']

    groupedbycols = ['Rule Title','Description','Implication','Recommendation','References','Account','Severity','Status','Scoring','Resource Type']
    tocombinecrlf = ['Region','Resource','Resource Name','Notes']
    dfvulnsbytitle=dfvulnsbytitle.sort_values(by=groupedbycols).reset_index(drop=True)
    dfvulnsbytitle[tocombinecrlf]=pd.DataFrame(dfvulnsbytitle.groupby(groupedbycols)[tocombinecrlf].transform(lambda x: '\n'.join(sorted(x.unique()))))



    # Output to Excel
    dfvulnsbytitle[outputcols].drop_duplicates().reset_index(drop=True).to_excel(writer2, sheet_name='ConsolidatedIssuesByTitle', index=False)

    writer2.save()





# run this script from command line: python nexpose_netva_2_csv
if len (sys.argv) < 2 :
    print("Usage: "+os.path.basename(__file__) +" WardenChecks.csv>")

    print("Note: No Trailing slash for fodlers")
    print("Exiting ...")
    sys.exit (1)
elif os.path.isfile(sys.argv[1]):

    inputFile=sys.argv[1]
    print(inputFile, ' is a File')
    #processFile(inputFile)
    mergeconsolidatebytitle(inputFile)

else:
    sys.exit (1)





    
    



