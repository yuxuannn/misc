import sys, os, csv, re, ipaddress
from lxml import etree as ET
#from pptx.dml.color import RGBColor
# pip3 install python-pptx not pip3 install pptx
from cvss import CVSS2, CVSS3
import pandas as pd



def convertCVSS2toCVSS3(cvss2):
    #cvss2='AV:L/AC:M/Au:S/C:C/I:C/A:P'
    cvss2arr=cvss2.split('/')
    cvss3='AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    #print(cvss2)
    #print(cvss3)
    #print(cvss2arr)
    
    cvss3arr=cvss3.split('/')
    cvss3arr[0]=cvss2arr[0]
    if cvss2arr[1]=='AC:L':
        cvss3arr[1]=cvss2arr[1]
    else:
        cvss3arr[1]='AC:H'

    if cvss2arr[2]=='Au:N':
        cvss3arr[2]='PR:N'
    else:
        cvss3arr[2]='PR:L'


    for num in range(3,6):
        #print(num)
        #print(cvss2arr[num], cvss3arr[num+2])
        (metric, value)=cvss2arr[num].split(':')
        #print(value)
        if value=='N':
            cvss3arr[num+2]=metric+':'+'N'
        elif value=='P':
            cvss3arr[num+2]=metric+':'+'L'
        elif value=='C':
            cvss3arr[num+2]=metric+':'+'H'    



    #print(cvss3arr)
    cvss3='CVSS:3.0/'+'/'.join(cvss3arr)
    #print(cvss3)
    return cvss3

def mapCVSS3toScore(cvss3Vector):
    c = CVSS3(cvss3Vector)
    return c.scores()[0]

# parse complicated nodes with different nested tags
def scrapenode(elem, tag):
    #print(elem.attrib)
    fullvuln=[]
    
    # iterate through all child elements recursively?
    for element in elem.getiterator():
        
        #if element.tag == 'solution':
        ''' old
        if element.tag == tag:
            continue
        else:
            tmp=[''+key+ ' : '+element.attrib.get(key) for key in element.attrib.keys()]
            fullvuln.append(str(tmp))
        
        '''
        if element.tag == 'URLLink':
            fullvuln.append(element.attrib.get('LinkURL'))
        
        if element.text:
            
            text=re.sub(r'\n+', '\n', element.text).strip()
            text=re.sub(r'\r+', '\r', text).strip()
            # remove duplicated space
            text=re.sub(' +', ' ', text).strip()
            #print(element.text)
            fullvuln.append(text)

    fullvuln='\n'.join(fullvuln).replace('\r', '').replace('\t','').replace('[]','')
    # /replace-multiple-newlines-with-single-newlines-during-reading-file
    fullvuln = re.sub(r'\n+', '\n', fullvuln).strip()
    
    return fullvuln

    
def mapassettype(ipaddr):
    try:
        addr = ipaddress.IPv4Address(ipaddr)
    except ValueError:
        #raise # not an IP address
        return 'UNKNOWN'
    if addr.is_private:
        return 'INT' # is a private address
    else:
        return 'EXT'
    '''
    if ipaddr in ['61.8.245.52','122.11.168.160','61.8.245.50','61.8.245.53','40.90.176.90','202.79.195.76','202.79.195.81','202.79.195.82']:
        return 'EXT'
    elif ipaddr in ['10.90.1.39','10.90.1.37','10.90.1.31','10.90.1.65','10.90.1.2','10.90.1.28','10.90.15.5','192.168.90.6']:
        return 'INT'
    else:
        return 'UNKNOWN'
    '''


def CVSSSeverity(score):
    # convert back to float 
    score=float(score)
    if score >= 9.0 and score <= 10.0:
        severity='CRITICAL'
    elif score >= 7.0 and score <= 8.9:
        severity='HIGH'
    elif score >= 4.0 and score <= 6.9:
        severity='MEDIUM'        
    elif score >= 0.1 and score <= 3.9:
        severity='LOW'
    elif score == 0:
        severity='NONE'
    else:
        raise ValueError()
    return severity

def CVSSSeverity2(score):
    # convert back to float 
    score=float(score)
    if score >= 9.0 and score <= 10.0:
        severity='Critical'
    elif score >= 7.0 and score <= 8.9:
        severity='High'
    elif score >= 4.0 and score <= 6.9:
        severity='Medium'        
    elif score >= 0.1 and score <= 3.9:
        severity='Low'
    elif score == 0:
        severity='Information'
    else:
        raise ValueError()
    return severity

# Map HTTP/HTTPS to HTTP(S) and combine by Issue Name (aggregate Issue Evidence too)
def mapsvc(x):
    if x=='HTTP':
        return 'HTTP(S)'
    elif x=='HTTPS':
        return 'HTTP(S)'
    else:
        return x

# Add Service Name to Title as prefix if not present within title
def addsvcname2title(data2):
    #print (data2.apply(lambda x: x['Service Name'] in x['Description'] and x['Service Name'] != "'", axis=1).head(5))
    searchindex=data2.index[data2.apply(lambda x: x['Service Name'] not in x['title'] and x['Service Name'] != "'", axis=1)].tolist()
    print(searchindex)
    #tmp= data2.loc[searchindex][['Service Name','Description']]
    #data2tmp=data2.loc[searchindex].apply(lambda x: x['title']='(' +x['Service Name']+ ')'+x['title'], axis=1)
    #data2.loc[searchindex].apply(lambda x: print(x['title']), axis=1)
    #data2.loc[searchindex]['title']='(' +data2.loc[searchindex]['Service Name']+ ')'+data2.loc[searchindex]['title']
    data2tmp=data2.loc[searchindex]
    #data2.loc[searchindex]=data2tmp.assign(title='(' +data2.loc[searchindex]['Service Name']+ ') '+data2.loc[searchindex]['title'])
    data2.loc[searchindex]=data2tmp.assign(title=data2.loc[searchindex]['Service Name']+ ' - '+data2.loc[searchindex]['title'])
    #return data2tmp



# Compress rows according to asset type (if defined, else default REF)
def merge_rows4(df, searchindex, newcol, counter):
    
    if searchindex:
        #print(searchindex)
        df1 = df.loc[searchindex]
        df1['key'] = 'a'
        #df2=df1.groupby(['key']).transform(lambda x : '**\n'.join(x))
        #print(df1[['title', 'cvssScore']])
        #print(df1['cvssScore'].max())
        # simplify risk
        #for risk in ['Critical', 'High', 'Medium', 'Low']:
            #df2['Risk'][df2['Risk'].str.contains(risk, case=False)]=risk

        #df2['Host:port']=df2['Host:port'].map(lambda x: simplifyhostport(x))

        df1['REF']=newcol
        #df1['REF-ID']='REF-'+str(counter)
        df1['REF-ID']=df1['AssetType']+'-'+str(counter)
        print(df1['cvssScore'].max())
        df1['Overall CVSS']=df1['cvssScore'].max()
        
        df.loc[searchindex]=df1
        #print(df2)
        #df.loc[searchindex]=df2        
        #return df


def extractnexposevulndefns2(root):

    '''  Extract the Vulns KB/Definitions out '''
    #fields=['id', 'title', 'cvssVector', 'cvssScore', 'Description', 'Solution', 'Exploits','References',  'Tags', 'Malware', 'Malware-Raw', 'Description-Raw']

    fields=['id', 'Risk', 'title', 'Description', 'Solution','cvssScore', 'cvssVector', 'Exploits','References',  'Tags', 'Malware', 'Malware-Raw', 'Description-Raw']
    #filename=filename+"-vulns.csv"
    #outputfile=os.path.join(os.getcwd(),filename)
    #print(outputfile)
    #outputfile='vulns.csv'

    listofchecks=[]
    for vuln in root.findall("./VulnerabilityDefinitions/vulnerability"):
        #print(vuln.attrib)

        vulndict = {key: None for key in fields}
        #print(vulndict)

        id=vuln.attrib.get('id')
        title=vuln.attrib.get('title')
        cvssVector=vuln.attrib.get('cvssVector')
        cvssScore=vuln.attrib.get('cvssScore')
        #cvssSeverity=CVSSSeverity(cvssScore)

        description=vuln.find('description')
        references=vuln.find('references')
        exploits=vuln.find('exploits')
        solutions=vuln.find('solution')
        tags=vuln.find('tags')
        malware=vuln.find('malware')
        #print(ET.tostring(description))
        #print(ET.tostring(solutions))
        #print(ET.tostring(tags))
        #print(tags)
        tags2=[elem.text for elem in vuln.findall("./tags/tag")]
        malware2=[elem.text for elem in vuln.findall("./malware/name")]
        #print(tags2)
        refs2=[(elem.attrib.get('source')+': '+elem.text) for elem in vuln.findall("./references/reference")]
        refs2='\n'.join(refs2)
        #refs2=[elem.attrib.get('source') for elem in vuln.findall("./references/reference")]

        #for elem in vuln.findall("./references/reference"):
            #print(elem.attrib.get['source'])
        desc="'"
        if description:
            for elem in description:
                desc=scrapenode(elem, 'description')        

        #print(refs2)    
        solns="'"
        if solutions:
            for elem in solutions:
                solns=scrapenode(elem, 'solution')
                #print(solns)
                #print()

        exploit="'"        
        if exploits:
            for elem in exploits:
                exploit=scrapenode(elem, 'exploits')
                #print(exploit)
                #print()



        vulndict['id']=vuln.attrib.get('id')
        vulndict['title']=vuln.attrib.get('title')
        vulndict['cvssVector']=vuln.attrib.get('cvssVector')[1:-1]
        vulndict['cvssScore']=vuln.attrib.get('cvssScore')
        vulndict['Risk']=CVSSSeverity(vulndict['cvssScore'])
        vulndict['Description']=desc
        vulndict['Solution']=solns
        vulndict['Exploits']=exploit
        vulndict['References']=refs2
        vulndict['Tags']=tags2
        vulndict['Malware']=malware2
        vulndict['Malware-Raw']=ET.tostring(malware)
        vulndict['Description-Raw']=ET.tostring(description)


        #csvfile.writerow([id, title, cvssVector, cvssScore, desc, solns, exploit, refs2, tags2, malware2, ET.tostring(malware), ET.tostring(description) ])
        listofchecks.append([ vulndict[key] for key in list(vulndict.keys()) ])

    dfvulnskb=pd.DataFrame(listofchecks, columns=fields)
    dfvulnskb=dfvulnskb.sort_values(by=['id'])
    dfvulnskb['CVSS3 Vector']=dfvulnskb['cvssVector'].map(convertCVSS2toCVSS3)
    dfvulnskb['CVSS3 Base Score']=dfvulnskb['CVSS3 Vector'].map(mapCVSS3toScore)
    dfvulnskb['Risk']=dfvulnskb['CVSS3 Base Score'].map(CVSSSeverity)

    #df1=dfvulnskb
    return dfvulnskb

def extractnexposefindings2(root):
    ''' Extract the findings with affected hosts and ports '''
    # rename Issue Evidence to Test Output
    fields=['Scan ID', 'Test ID', 'Test Output', 'Full Test Output', 'IP Address', 'Port', 'Service Name', 'Protocol', 'HostPort','Hostnames', 'Vuln Attributes', 'Node Attributes']
    #filename=filename+"-findings.csv"
    #outputfile=os.path.join(os.getcwd(),filename)
    #outputfile='findings.csv'



    listofresult=[]

    for vuln in root.findall("./nodes/node/tests/test"):
        #print(vuln.attrib)

        fullvuln=scrapenode(vuln, 'test') 


        vuln_node=vuln.getparent().getparent()
        ip=vuln_node.attrib.get('address')
        #print(ip)
        #fingerprints=vuln_node.findall("./fingerprints")


        hostnames=[hostname.text for hostname in vuln_node.findall("./names/name")]
        #osfingerprints=vuln_node.findall("./fingerprints/os")
        fingerprints=[elem.attrib for elem in vuln_node.findall("./fingerprints/os")]
        # TypeError: sequence item 0: expected str instance, lxml.etree._Attrib found
        #fingerprints='\n'.join(fingerprints)

        '''
        if fingerprint:
            print(fingerprint)

            fingerprints=[elem.attrib.get(key) for key in fingerprint.attrib.keys()]
            #fingerprints='\n'.join([elem.attrib for elem in vuln_node.findall("./fingerprints/os")])

        else:
            fingerprints=[]

        fingerprints='\n'.join(fingerprints)

        '''

        #print(hostnames)
        #print(fingerprints)
        port=""
        servicename=""
        proto=""
        hostport=ip
        # fields=['Issue ID', 'Issue', 'Issue Description', 'IP Address', 'Port', 'Hostnames']
        #csvfile.writerow([vuln.attrib.get('scan-id'), vuln.attrib.get('id'), fullvuln, ET.tostring(vuln), ip, port, servicename, proto, hostnames, vuln.attrib, vuln_node.attrib])
        listofresult.append([vuln.attrib.get('scan-id'), vuln.attrib.get('id'), fullvuln, ET.tostring(vuln), ip, port, servicename, proto, hostport, hostnames, vuln.attrib, vuln_node.attrib])



    for vuln in root.findall("./nodes/node/endpoints/endpoint/services/service/tests/test"):
        #print(vuln.attrib)

        fullvuln=scrapenode(vuln, 'test') 


        service=vuln.getparent().getparent()
        endpoint=service.getparent().getparent()
        vuln_node=endpoint.getparent().getparent()
        # endpoint.attrib.get(['protocol', 'port'])

        #print(service.attrib.get('name'), endpoint.attrib.get('protocol'), endpoint.attrib.get('port'))


        #print(vuln_node.tag)
        #print(vuln_node.attrib)
        ip=vuln_node.attrib.get('address')
        #print(ip)

        #port=[service.attrib.get('name'), endpoint.attrib.get('protocol'), endpoint.attrib.get('port')]
        port=endpoint.attrib.get('port')
        servicename=service.attrib.get('name')
        proto=endpoint.attrib.get('protocol')
        hostport=ip+':'+port+' ('+proto+')'


        # convert simple array to 
        hostnames=[hostname.text for hostname in vuln_node.findall("./names/name")]
        #print(hostnames)
        #csvfile.writerow([vuln.attrib.get('scan-id'), vuln.attrib.get('id'), paragraph.text, fullvuln, ip, port, hostnames, vuln.attrib, vuln_node.attrib])
        #csvfile.writerow([vuln.attrib.get('scan-id'), vuln.attrib.get('id'), fullvuln, ET.tostring(vuln), ip, port, servicename, proto, hostnames, vuln.attrib, vuln_node.attrib])

        # fields=['Issue ID', 'Issue', 'Issue Description', 'IP Address', 'Port', 'Hostnames']
        listofresult.append([vuln.attrib.get('scan-id'), vuln.attrib.get('id'), fullvuln, ET.tostring(vuln), ip, port, servicename, proto, hostport, hostnames, vuln.attrib, vuln_node.attrib])

    dffindings=pd.DataFrame(listofresult, columns=fields)
    dffindings=dffindings.sort_values(by=['Test ID'])
    #df2=dffindings
    return dffindings




def nexpose2csv() :
    print(2)
    #inputFile=sys.argv[2]
    inputFile=sys.argv[1]
    (baseFolder, basename)=os.path.split(inputFile)
    print(baseFolder, basename)
    (filename, fileext)=os.path.splitext(basename)
    print(filename, fileext)

    outputFile1=os.path.join(baseFolder, filename+'-results.csv')
    outputFile2=os.path.join(baseFolder, filename+'-results.xlsx')
    tree=ET.parse(inputFile)
    root=tree.getroot()    

    
    
    df1=extractnexposefindings2(root)
    df2=extractnexposevulndefns2(root)

    df4=df1[['Service Name','Test ID', 'Test Output', 'IP Address','Port','Protocol', 'HostPort','Hostnames']]
    # Sort by <Service Name, Test ID>
    df4=df4.sort_values(by=['Service Name','Test ID']).reset_index(drop=True)
    #df4=df4.assign(AssetType=df4['Service Name'])
    # Add New Column, Asset Type
    df4['AssetType']=df4['IP Address'].map(mapassettype)
    # Add New Column
    #df4=df4.assign(agghostport=df4['IP Address']+':'+df4['Port'] + ' (' + df4['Protocol'] +')')
    #df4['agghostport']=df4['IP Address']+':'+df4['Port'] + ' (' + df4['Protocol'] +')'
    #df4=df4.assign(servicename2=df4['Service Name'])
    df4['servicename2']=df4['Service Name']
    df4['Service Name']=df4['servicename2'].map(mapsvc)

    # Aggregate Affected IP Addr & Port by Assset Type, Service Name, Test ID and Evidence
    df4[['HostPort']]=pd.DataFrame(df4[['AssetType','Service Name', 'Test ID', 'Test Output', 'HostPort']].groupby(['AssetType','Service Name', 'Test ID', 'Test Output'])['HostPort'].transform(lambda x: '\n'.join(x)))
    df4=df4[['Service Name', 'Test ID', 'Test Output','HostPort','AssetType']].drop_duplicates().reset_index(drop=True)
    #

    # Aggregate Affected IP Addr & Port again by Assset Type, Service Name, Test ID
    df5=df4
    df5['Test Output']=df5['Test Output']+'\n'+df5['HostPort']
    df5[['HostPort','Test Output']]=pd.DataFrame(df5[['AssetType','Service Name', 'Test ID', 'Test Output', 'HostPort']].groupby(['AssetType','Service Name', 'Test ID'])['HostPort','Test Output'].transform(lambda x: '\n'.join(x)))
    df5=df5[['Service Name', 'Test ID', 'Test Output','HostPort','AssetType']].drop_duplicates().reset_index(drop=True)
    #df5=df5[['Service Name','Test ID', 'title', 'AssetType','HostPort', 'Description', 'Issue Evidence', 'cvssSeverity', 'Solution', 'cvssScore', 'cvssVector', 'Exploits', 'References', 'Tags', 'Malware']]
    #df5=df5[['Service Name','Test ID', 'title', 'AssetType','HostPort', 'Description', 'Issue Evidence', 'cvssSeverity', 'Solution', 'cvssScore', 'cvssVector']].drop_duplicates().reset_index(drop=True)
    #df5=df5.drop_duplicates().reset_index(drop=True)
    #df4.to_csv('foroutput.csv')

    df6=pd.merge(df5,df2, left_on='Test ID', right_on='id')
    # keep original names for Outdated Softwares' CVEs
    df6['Name'] = df6['title']
    df6=df6[['Risk','CVSS3 Base Score','Service Name','Test ID','title','Description','Solution','AssetType','HostPort','Name','Test Output','CVSS3 Vector','cvssScore','cvssVector','Exploits','References','Tags','Malware','Malware-Raw','Description-Raw']]
    # Add Service Name to Title
    addsvcname2title(df6)
    df6['Description']=df6['title']+'\n'+df6['Description']

    # Rename Columns
    #df6.rename(columns={'cvssSeverity': 'Risk'}, inplace=True)
    #df6['Overall Risk']=df6['Overall CVSS'].map(CVSSSeverity)
    df6=df6.sort_values(by=['AssetType','Test ID', 'Risk'])


    df6.to_csv(outputFile1)
    df6.to_excel(outputFile2)

    print('Output CSV File: '+outputFile1)
    print('Output Excel File: '+outputFile2)

# run this script from command line: python nexpose_netva_2_csv
if len (sys.argv) < 2 :
    #print("Usage: python "+os.path.basename(__file__) +" 'nexpose2csv' <inputfile>")
    print("Usage: "+os.path.basename(__file__) +" <xml export 2.0>")
    print("Exiting ...")
    sys.exit (1)
else:
    nexpose2csv()