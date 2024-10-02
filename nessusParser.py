import os
import re
import glob
import pandas as pd

#change as necessary
os.chdir("/mnt/hgfs/phryne/")

#set extension to csv, grab all .csv files in working directory
extension = 'csv'
all_filenames = [i for i in glob.glob('*.{}'.format(extension))]

#combine all files in the list
df = pd.concat([pd.read_csv(f) for f in all_filenames ])
orig_df = df

#drop duplicate findings from recurring scans
df = df.drop_duplicates(subset=['Name', 'Host', 'Port', 'CVE'])

#remove duplicate hosts in each finding (NaN)
df = df.sort_values(by=['Name', 'Host', 'Port'], ascending=True)
df['Host'] = df['Host'].mask(df.duplicated(['Name', 'Host']))

#add host+proc+port
df['AffectedModules'] = (df['Host'].astype(str) + " (" + df['Protocol'].astype(str) + '/' + df['Port'].astype(str) + ')')

#aggregate by finding name
df = df.astype(str).groupby('Name').agg(lambda x: ', '.join(x.unique()))

#clean up NaNs
df['AffectedModules'] = df['AffectedModules'].replace({'\), nan \(' : ', '}, regex=True)
df['AffectedModules'] = df['AffectedModules'].replace({'\),' : ')\n'}, regex=True)
df['Host'] = df['Host'].replace({', nan' : ''}, regex=True)
df = df.apply(lambda col: col.str.replace('nan', '-'))


#print to console & export to xlsx
print(df)
with pd.ExcelWriter('merge.xlsx') as writer:  
    df.to_excel(writer, sheet_name='merge')
    orig_df.to_excel(writer, sheet_name='original')
#df.to_excel('merge.xlsx')

#references
#https://stackoverflow.com/questions/62926346/merging-pandas-dataframe-on-unique-values-in-a-column
#https://stackoverflow.com/questions/67298427/replace-duplicate-value-with-nan-using-groupby
#https://stackoverflow.com/questions/54133679/aggregate-unique-values-from-multiple-columns-with-pandas-groupby
#https://stackoverflow.com/questions/17141558/how-to-sort-a-dataframe-in-python-pandas-by-two-or-more-columns
#https://stackoverflow.com/questions/38565849/pandas-replace-substring-in-string
#https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.to_excel.html
