##############################################################################################
#
#        P.assword
#        R.ecovery
#        A.nalysis
#        T.ool
#
#   Author: Bradley Mumme
#   Current Version: 2.2
#   Version Date: 04/22/24
#
#   Last Update: Added -a for active AD user correlation and additional password metrics
#
#   Example Usage:
#   python3 prat.py -m 2 -i hashcatoutput.txt -s secretsdumpoutput.txt -o nameofworkbook.xlsx
#   **
#   **  All Arguments shown above are required
#   **  You can select between three modes (e.g., -m 1 or -m 2 or -m 3)
#   **  You can specify name of txt files located anywhere but the output file
#   **  must only be name of the file not including a directory. The file will
#   **  be included in the same directory as the script.
#   **
#
###############################################################################################



import pandas as pd
from pandas import ExcelWriter
from pandas import ExcelFile
import string
import re
import time
import argparse
import chardet
from pyfiglet import Figlet
from pwnedapi import Password
from tqdm import tqdm


custom_fig = Figlet(font='speed')
#custom_fig = Figlet(font='invita')
print(custom_fig.renderText('P.R.A.T.'))
print("  Title: P.assword R.ecovery A.nalysis T.ool")
print("  Author: Bradley Mumme")
print("  Version: 2.2 - April 2024")
print('')



parser = argparse.ArgumentParser()



parser.add_argument('-m','--mode', choices=(1,2,3), type=int,required=True, action='store',
help='Choose the type of analysis \n Option 1: This mode will analyze password compliance based on if password contains a special character, a number, an upper and lower case letter, and is at least 8 characters Option 2: This mode is the custom mode. This will enable you to specify what types of requirements the password is required to have. Option 3: This options is useful for specifying how many requirments out of the four standard requirements the password must have. (e.g., three our of four requirements must be met and the password must be n characters long.)')
parser.add_argument('-i','--inputfile', metavar='crackedPasswords', type=argparse.FileType('r'), required=True,
help='Specify the location of the text file storing the recovered passwords. Format = hash:password.  A txt file containing the dump of the hashcat .pot file is the best choice.')
parser.add_argument('-o', '--outputfile', metavar='out-file', action='store', required=True,
help='Specify the name of the excel analysis workbook. NOTE: this does not accept directories. Please only put the name of the file as it will be saved in your current directory')
parser.add_argument('-s', '--secretsdumpImport', metavar='secretsdump-import', type=argparse.FileType('r'), required=True,
help='The name of the txt file that is the output from the secretsdump.py script. This is used to correlate passwords to users. ')
parser.add_argument('-a', '--activeUsers', metavar='active-users', type=argparse.FileType('r'),
help='Specify the CSV containing active users to correlate password findings to only active users\nOnly include the SAM name (e.g., "bmumme")')
#parser.add_argument('-o','--outputfile', metavar='out-file', type=argparse.FileType('wt'), help='Specify the location and name of the excel analysis workbook')

args = parser.parse_args()

stagger_time = 1

secretsDumpFile = args.secretsdumpImport
passfile = args.inputfile
output = args.outputfile
activeFile = args.activeUsers

#output file validation
#adds '.xlsx' if necessary
if output[-5:] != '.xlsx':
    output = output + '.xlsx'
else:
    pass

filler = "********************"
#Begin Displaying information to user
print("***** Initializing *****")
print('')
time.sleep(stagger_time)
print('The output will be stored in the following excel workbook located in the current directory:  ' + output + "\n")


d2cols = ['User', 'rid', 'HashType', 'PassHash', 'na1', 'na2', 'na3']
d3cols = ['Username']
df_2 = pd.read_csv(secretsDumpFile, sep=":|,", engine='python', on_bad_lines='skip', names=d2cols, skipinitialspace=True)
df_2 = df_2[pd.notnull(df_2['PassHash'])]
df_2 = df_2[df_2.User.str.contains('\\\\')]
allhashes = df_2['PassHash'].count()

#active user dataframe
if args.activeUsers:
    print(filler + "\nFindings will only show Active Users\n" + filler)
    activeFile = args.activeUsers
    df_3 = pd.read_csv(activeFile, sep=":|,",encoding='utf-8', engine='python', on_bad_lines='skip', names=d3cols, skipinitialspace=True)

else:
    print(filler +"\n No Active User File Specified\n" + filler)
#d1cols = ['PassHash', 'Password']
#df = pd.read_csv(passfile, sep=":|,", engine='python', on_bad_lines='skip', names=d1cols)

#special characters
#V-2.1 determines encoding type
rawdata = open(str(passfile.name),"rb").read()
encodingType = chardet.detect(rawdata)['encoding']
#V-1.1 open txt file and transform it to include passwords that have a ',' and Other
with open(str(passfile.name),encoding=str(encodingType), errors='replace') as p:
    initList = p.readlines()
newlist = [i.split('\n',1)[0] for i in initList]
s = pd.Series(newlist)
s = s.str.split(pat=':', expand=True,n=1)
df = pd.DataFrame(s)
df.columns = ['PassHash', 'Password']

df = df[pd.notnull(df['Password'])]

regex = re.compile(r'[.,@_!#$%^&*()<>?/\|}{~:]')

Users = df_2['User']
HashcatHashes = df_2['PassHash']
CompanyNames = []
PasswordList = df['Password']
PasswordHash = df['PassHash']
LengthList = []
SpecialCharList = []
LowerCase = []
UpperCase = []
NumberList = []
ContainsCompany = []
ComplianceCount = []
CustomComplianceCount = []
ConsecutiveNumber= []
#Array of top 25 cracked passwords and the word 'pass' according to
Top25passwords = [ 'pass','123456', 'password', '123456789', '12345678', '12345', '111111', '1234567', 'sunshine', 'qwerty', 'iloveyou', 'princess', 'admin', 'welcome', '666666', 'abc123', 'football', '123123', 'monkey', '654321', '!@#$%^&*', 'charlie', 'aa123456', 'donald', 'password1', 'qwerty123']
Seasons = ['winter','summer','fall','spring','autumn']
ContainsSeason = []
ContainsCommonPassword = []
ContainsPwd = []
#Array to contain if password has been pwned according to HaveIBeenPwned
PwnedPasswords = []


writer = ExcelWriter(output, engine='xlsxwriter')
workbook = writer.book
worksheet = workbook.add_worksheet('Dashboard')
tablesheet = workbook.add_worksheet('MostOccuringPasswords')
writer.sheets['TableData'] = tablesheet
rawdatasheet = workbook.add_worksheet('Raw_Data')
writer.sheets['Raw_Data'] = rawdatasheet

#Determine Actions based on if active user list provided
if args.activeUsers:
    activesheet = workbook.add_worksheet('ActiveUsers')
    writer.sheets['ActiveUsers'] = activesheet
    df_3.to_excel(writer,sheet_name='ActiveUsers',index=False)
    status = 'ACTIVE '
else:
    status = ''






#function that analyzes password for generic data. Performed on any mode
def magic():
    for word in PasswordList:
        passLength = len(str(word))
        LengthList.append(int(passLength))
        if regex.search(str(word))== None:
            SpecialCharList.append(0)
        else:
            SpecialCharList.append(1)

        if any(c.islower() for c in str(word)):
            LowerCase.append(1)
        else:
            LowerCase.append(0)

        if any(c.isupper() for c in str(word)):
            UpperCase.append(1)
        else:
            UpperCase.append(0)

        if any(c.isdigit() for c in str(word)):
            NumberList.append(1)
        else:
            NumberList.append(0)

        if any(name.lower() in word.lower() for name in CompanyNames):
            ContainsCompany.append(1)
        else:
            ContainsCompany.append(0)

        if any(name.lower() in word.lower() for name in Top25passwords):
            ContainsCommonPassword.append(1)
        else:
            ContainsCommonPassword.append(0)

        if any(name.lower() in word.lower() for name in Seasons):
            ContainsSeason.append(1)
        else:
            ContainsSeason.append(0)

        if "password" in word.lower():
            ContainsPwd.append(1)
        else:
            ContainsPwd.append(0)

    if checkPwn == 'Y':
        for word in tqdm(PasswordList):
            password = Password(word)
            if password.is_pwned():
                PwnedPasswords.append(1)
            else:
                PwnedPasswords.append(0)
    else:
        pass

#function to pass results to do analysis and write to dashboard
def new_Analysis(results):
    totalhashes = results['PassHash'].count()
    pwdsRecovered = totalhashes - (results[results["Password"] == 'Password Not Recovered'].count()["Password"])
    longPass = results["PasswordLength"].max()
    shortpass = results["PasswordLength"].min()
    goodpwds = results[results["Compliance"] == 'GOOD'].count()["Compliance"]
    missingrq = results[results["Compliance"] == 'Missing Requirement'].count()['Compliance']
    tooshort = results[results["Compliance"] == 'Too Short'].count()['Compliance']
    totalbad = missingrq + tooshort
    amtnumber = results['IsNumber?'].sum()
    amtspecial = results['HasSpecialChar?'].sum()
    amtSeasons = results['ContainsSeason'].sum()
    amtpwds = results['ContainsPassword'].sum()
    if checkPwn == 'Y':
        pwdspwned = results['PasswordPwned?'].sum()
    else:
        pass
    numtop25 = results['Top25Password'].sum()
    numco = results['ContainsCompany'].sum()
    #percentages
    pctRecovered = (pwdsRecovered/totalhashes)
    pctOut = (totalbad/pwdsRecovered)
    pctMissingRQ = (missingrq/pwdsRecovered)
    pctInCompliance = (goodpwds/pwdsRecovered)
    pctTooShort = (tooshort/pwdsRecovered)
    pctNumber = (amtnumber/pwdsRecovered)
    pctSpecialChar = (amtspecial/pwdsRecovered)
    pctPwds = (amtpwds/pwdsRecovered)
    if checkPwn == 'Y':
        pctPwned = (pwdspwned/pwdsRecovered)
    else:
        pass


    pctTop25 = (numtop25/pwdsRecovered)
    pctCoName = (numco/pwdsRecovered)
    pctSeason = (amtSeasons/pwdsRecovered)

    print('')
    print('***** Analyzing *****')
    print('')
    time.sleep(stagger_time)
    print('Total User Hashes Recovered: ' + str(allhashes))
    if args.activeUsers:
        print('Total ACTIVE User Hashes Recovered: ' + str(totalhashes))
    print("Amount of Passwords in Compliance: " + str(goodpwds))
    print("Amount of Passwords Missing a Requirement: " + str(missingrq))
    print("Amount of Passwords that are too short: " + str(tooshort))
    print("Amount of Passwords Recovered: " + str(pwdsRecovered))
    print("Percentage of Passwords Recovered: " + str((pwdsRecovered/totalhashes)*100))
    print('**********')

    cleanone = results.loc[results['Password'] != 'Password Not Recovered']
    dupPwds = cleanone.groupby('Password').size()
    newp = dupPwds.sort_values(axis=0,ascending=False)
    newnewp = newp.nlargest(20)
    printp = newp.nlargest(5)
    newnewp.to_excel(writer,sheet_name='TableData',startrow=1)

    print('Top 5 Most Occuring Passwords:')
    print(printp)
    avgpwdLength = results['PasswordLength'].mean()

    print('**********')
    print('Number of Passwords Containing a form of Company Name: ' + str(numco))
    print("Percentage of Recovered Passwords Out of Compliance: " + str(pctOut))
    print('Total Passwords Containing a Number: ' + str(results['IsNumber?'].sum()))
    print('Total Number of Passwords Containing a Season: ' + str(amtSeasons))
    print('Average Password Length : ' + str(results['PasswordLength'].mean()))

    #format Dashboard
    percent_fmt = workbook.add_format({'num_format': '0.0%','border':True, 'center_across':True})
    header_fmt = workbook.add_format({'bold': True, 'font_color':'white', 'bottom':True, 'bg_color':'385872'})
    header_fmt2 = workbook.add_format({'bold': True, 'font_color':'white', 'bottom':True, 'bg_color':'385872', 'center_across':True})
    merge_fmt = workbook.add_format({'bold': True, 'font_color':'white', 'bottom':True, 'bg_color':'385872', 'center_across':True})
    sub_header_fmt = workbook.add_format({'font_color': 'white', 'bg_color':'gray', 'bottom':True})
    sub_header_fmt2 = workbook.add_format({'font_color': 'white', 'bg_color':'gray', 'bottom':True, 'center_across':True})
    table_head_fmt = workbook.add_format({'font_color': 'white', 'bg_color':'gray', 'bottom':True, 'center_across':True})
    tag_fmt = workbook.add_format({'border':True})
    num_fmt = workbook.add_format({'border':True, 'center_across':True})
    table_desc_fmt = workbook.add_format({'border':True,'bg_color': '748a9c','font_color':'black'})
    blank_fmt = workbook.add_format({'bold': True, 'center_across':True})

    #Table DAta Worksheet
    tablesheet.set_column('A:A',20)
    tablesheet.write(0,0,'Top 20 Most Occuring Passwords',header_fmt)
    tablesheet.merge_range('A1:B1', 'Top 20 Most Occuring Passwords', merge_fmt)
    tablesheet.write(1,0,'Password',table_head_fmt)
    tablesheet.write(1,1, 'Occurences', table_head_fmt)
    #tablesheet.set_row(2,, num_fmt)
    #tablesheet.set_column(1,1,20,num_fmt)
    tablesheet.set_column(1,1,20,blank_fmt)


    worksheet.set_column('A:A',50)
    worksheet.set_column('B:B',12)
    worksheet.set_column('C:C', 12)
    worksheet.write(0,0,'High Level Results',header_fmt)
    worksheet.write(1,0,'Total '+ status + 'User Accounts Returned',tag_fmt)
    worksheet.write(2,0,'Total ' + status + 'User Passwords Recovered (Cracked)',tag_fmt)
    worksheet.write(3,0,'Compliance Results',header_fmt)
    worksheet.write(4,0,status + 'User Passwords In Compliance',tag_fmt)
    worksheet.write(5,0,status + 'User Passwords Out of Compliance',tag_fmt)
    worksheet.write(6,0,'Out of Compliance Analysis', sub_header_fmt)
    worksheet.write(7,0,'Number of Passwords Missing a Requirement',tag_fmt)
    worksheet.write(8,0,'Number of Passwords Too Short',tag_fmt)
    worksheet.write(9,0,'Password Metrics', header_fmt)
    worksheet.write(10,0,'Average Password Length',tag_fmt)
    worksheet.write(11,0,'Longest Password',tag_fmt)
    worksheet.write(12,0,'Shortest Password',tag_fmt)
    worksheet.write(13,0,'Number of Passwords Containing a Number',tag_fmt)
    worksheet.write(14,0, 'Number of Passwords Containing a Special Character',tag_fmt)
    worksheet.write(15,0,'Other Important Metrics', header_fmt)
    worksheet.write(16,0,'Number of Passwords Exposed in a Breach',tag_fmt)
    worksheet.write(17,0,'Number of Passwords Containing Form of Top 25 Passwords',tag_fmt)
    worksheet.write(18,0,'Number of Passwords Containing Form of Company Name',tag_fmt)
    worksheet.write(19,0,'Number of Passwords Containing a Season', tag_fmt)
    worksheet.write(20,0,'Number of Passwords Containing "Password"', tag_fmt)

    worksheet.write(0,1,'',header_fmt)
    worksheet.write(1,1, totalhashes,num_fmt)
    worksheet.write(2,1, pwdsRecovered,num_fmt)
    worksheet.write(3,1, '',header_fmt)
    worksheet.write(4,1, goodpwds,num_fmt)
    worksheet.write(5,1, totalbad,num_fmt)
    worksheet.write(6,1, '', sub_header_fmt)
    worksheet.write(7,1, missingrq, num_fmt)
    worksheet.write(8,1, tooshort, num_fmt)
    worksheet.write(9,1, '', header_fmt)
    worksheet.write(10,1, avgpwdLength, num_fmt)
    worksheet.write(11,1, longPass,num_fmt)
    worksheet.write(12,1, shortpass,num_fmt)
    worksheet.write(13,1, amtnumber, num_fmt)
    worksheet.write(14,1, amtspecial, num_fmt)
    worksheet.write(15,1, '',header_fmt)
    if checkPwn == 'Y':
        worksheet.write(16,1, pwdspwned, num_fmt)
    else:
        pass
    worksheet.write(17,1, numtop25, num_fmt)
    worksheet.write(18,1, numco, num_fmt)
    worksheet.write(19,1, amtSeasons, num_fmt)
    worksheet.write(20,1, amtpwds, num_fmt)

    worksheet.write(0,2, '% of Total', header_fmt2)
    worksheet.write(1,2, '100%', num_fmt)
    worksheet.write(2,2, pctRecovered, percent_fmt)
    worksheet.write(3,2, '% of Recovered', header_fmt2)
    worksheet.write(4,2, pctInCompliance, percent_fmt)
    worksheet.write(5,2, pctOut, percent_fmt)
    worksheet.write(6,2, '', sub_header_fmt2)
    worksheet.write(7,2, pctMissingRQ, percent_fmt)
    worksheet.write(8,2, pctTooShort, percent_fmt)
    worksheet.write(9,2, '', header_fmt2)
    worksheet.write(10,2, '', num_fmt)
    worksheet.write(11,2, '', num_fmt)
    worksheet.write(12,2, '', num_fmt)
    worksheet.write(13,2, pctNumber, percent_fmt)
    worksheet.write(14,2, pctSpecialChar, percent_fmt)
    worksheet.write(15,2, '', header_fmt2)
    if checkPwn == 'Y':
        worksheet.write(16,2, pctPwned, percent_fmt)
    else:
        pass
    worksheet.write(17,2, pctTop25, percent_fmt)
    worksheet.write(18,2, pctCoName, percent_fmt)
    worksheet.write(19,2, pctSeason, percent_fmt)
    worksheet.write(20,2, pctPwds, percent_fmt)


#function to pass data to dataframe and write to excel
def raw_Data():
    if checkPwn == 'Y':
        df = pd.DataFrame({'PassHash':PasswordHash,
                           'Password': PasswordList,
                           'PasswordLength': LengthList,
                           'IsNumber?': NumberList,
                           'HasSpecialChar?': SpecialCharList,
                           'HasUpperCase?': UpperCase,
                           'HasLowerCase?': LowerCase,
                           'ContainsCompany': ContainsCompany,
                           'Compliance': ComplianceCount,
                           'Top25Password': ContainsCommonPassword,
                           'ContainsSeason': ContainsSeason,
                           'ContainsPassword': ContainsPwd,
                           'PasswordPwned?': PwnedPasswords})
    else:
        df = pd.DataFrame({'PassHash':PasswordHash,
                           'Password': PasswordList,
                           'PasswordLength': LengthList,
                           'IsNumber?': NumberList,
                           'HasSpecialChar?': SpecialCharList,
                           'HasUpperCase?': UpperCase,
                           'HasLowerCase?': LowerCase,
                           'ContainsCompany': ContainsCompany,
                           'Compliance': ComplianceCount,
                           'Top25Password': ContainsCommonPassword,
                           'ContainsSeason': ContainsSeason,
                           'ContainsPassword': ContainsPwd})

    results = df.merge(df_2, on = 'PassHash', how='right')
    new = results.User.str.split("\\", n=1, expand=True)
    results["Username"] = new[1]
    #results["Password"].fillna("Password Not Recovered", inplace=True)
    results.fillna({"Password": "Password Not Recovered"}, inplace=True)

    if args.activeUsers:
        newresults = results.merge(df_3, on = 'Username', how='right')
        new_Analysis(newresults)
        newresults.to_excel(writer,sheet_name='Raw_Data',index=False) 
    else:
        new_Analysis(results)
        results.to_excel(writer,sheet_name='Raw_Data',index=False)

#function for mode 3
def custom():
    Selected = []
    counter = -1
    while True:
        print('')
        print('**********')
        print('')
        print('You will be asked what requirements you want the passwords audited on.')
        print('')
        userSpecialChar = input('Do the passwords require a special character? (Y/n):  ')
        if not (userSpecialChar == 'Y' or userSpecialChar == 'n'):
            print("Sorry, you entered an invalid option. Try again and enter Y or n")
        else:
            break
        print('')
    while True:
        userLowerCase = input('Do the passwords require a lower case letter? (Y/n): ')
        if not (userLowerCase == 'Y' or userLowerCase == 'n'):
            print('Sorry, you entered an invalid option, Try again and enter Y or n')
        else:
            break
        print('')
    while True:
        userUpperCase = input('Do the passwords require an upper case letter? (Y/n): ')
        if not (userUpperCase == 'Y' or userUpperCase == 'n'):
            print('Sorry, you entered an invalid option, Try again and enter Y or n')
        else:
            break
        print('')
    while True:
        userNumber = input('Do the passwords require a number? (Y/n): ')
        if not (userNumber == 'Y' or userNumber == 'n'):
            print('Sorry, you entered an invalid option, Try again and enter Y or n')
        else:
            break
        print('')
    while True:
        try:
            userMinLength = int(input('What is the minimum length required of the passwords?: (enter 0 if there is no minimum) '))
            break
        except ValueError:
            print("Please input a number")
            continue
    magic()

    #array to check if all questions were answered no
    allNo = []

    if userSpecialChar == 'Y':
        Selected.append(SpecialCharList)
    else:
        allNo.append(1)

    if userLowerCase == 'Y':
        Selected.append(LowerCase)
    else:
        allNo.append(1)

    if userUpperCase == 'Y':
        Selected.append(UpperCase)
    else:
        allNo.append(1)

    if userNumber == 'Y':
        Selected.append(NumberList)
    else:
        allNo.append(1)

    summationArray = [sum(x) for x in zip(*Selected)]

    for word in PasswordList:
        amount = len(Selected)
        compliance = 0
        counter = counter +1
        if LengthList[counter] >= userMinLength:
            if len(allNo) == 4:
                ComplianceCount.append('GOOD')
            else:
                if summationArray[counter] == amount:
                    ComplianceCount.append('GOOD')
                else:
                    ComplianceCount.append('Missing Requirement')
        else:
            ComplianceCount.append('Too Short')
    raw_Data()

#function for mode 1
def complex():
    print('')
    print('**********')
    print('')
    magic()
    numvalues = len(PasswordList)
    counter = -1
    for word in PasswordList:
        counter = counter + 1
        if LengthList[counter] > 8:
            if NumberList[counter] + SpecialCharList[counter] + UpperCase[counter] + LowerCase[counter] == 4:
                ComplianceCount.append('GOOD')
            else:
                ComplianceCount.append('Missing Requirement')
        else:
            ComplianceCount.append('Too Short')
    raw_Data()


#function for mode 3
def outof():
    print('')
    print('**********')
    print('')
    print("")
    while True:
        try:
            userMinLength = int(input('What is the minimum length required of the passwords?: (enter 0 if there is no minimum) '))
            break
        except ValueError:
            print("Please input a number")
            continue
    while True:
        print('')
        print('How many requirements out of the following must your password meet\n'+
        '(Special Character, Number, UpperCase, LowerCase)\n'+
        'For Example: Password must meet three out of the four requirements\n')
        howmany = input('Enter the Number of requirements needed: ')
        if not int(howmany) < 5:
            print("Sorry, your number must be less than 5")
        else:
            break
    magic()
    counter = -1
    for word in PasswordList:
        counter = counter + 1
        if LengthList[counter] >= userMinLength:
            if NumberList[counter] + SpecialCharList[counter] + UpperCase[counter] + LowerCase[counter] >= int(howmany):
                ComplianceCount.append('GOOD')
            else:
                ComplianceCount.append('Missing Requirement')
        else:
            ComplianceCount.append('Too Short')
    raw_Data()



#Begin Generic Questions asked everytime
while True:
    print('')
    userInput = input("Please type company names to look for in password (seperate words by space): ")
    if any(c == ',' for c in userInput):
        print("Please type company names again SEPERATED BY A SPACE. Not by commas.")
    else:
        break

while True:
    checkPwn = input("Do you want to check passwords against the HaveIBeenPwned Database? (Y/n): ")
    if not (checkPwn == 'Y' or checkPwn == 'n'):
        print('Sorry, you entered an invalid option, Try again and enter Y or n')
    else:
        break
    print('')

#List of company names input by user
CompanyNames = userInput.split()


#Begin analysis based on mode selection
if args.mode == 1:
    complex()

if args.mode == 2:
    custom()

if args.mode == 3:
    outof()



print('')
print('*****************')
print('')
print('Writing to ' + output)
print('')
print('*****************')

time.sleep(stagger_time)




worksheet.set_zoom(110)
rawdatasheet.set_column('A:A', 10)
rawdatasheet.set_column('B:B', 10)
rawdatasheet.set_column('C:C', 10)
rawdatasheet.set_column('D:D', 10)
rawdatasheet.set_column('E:E', 10)
rawdatasheet.set_column('F:F', 10)
rawdatasheet.set_column('G:G', 10)
rawdatasheet.set_column('H:H', 10)
rawdatasheet.set_column('L:L', 20)

writer.close()
print('\nDONE!\n')
