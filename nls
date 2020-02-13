'Bulk nslookup to get IP addresses from supplied hostnames
'Hostname file should have hostnames delimited by newlines (.txt)
'Provide full file path to script when prompted, including extension
'Output file will be in .csv (output.csv) dropped in folder containing nsl.vbs

Option Explicit

'Object Shell
Dim objShell : Set objShell = WScript.CreateObject("WScript.Shell")

'Get hostname text & set output text
Dim strInputFile : strInputFile = InputBox("Please input full path to hostname text file", "nslookup")
Dim strLogFile : strLogFile = "output.csv" 
'Dim strHostname : strHostname = InputBox("Please input hostname", "nslookup")


Const intForReading = 1
Const intForWriting = 2
Const intForAppending = 8

'Object File System Object, Input File, Log File
Dim objFSO : Set objFSO = CreateObject("Scripting.FileSystemObject")
Dim objInputFile : Set objInputFile = objFSO.OpenTextFile(strInputFile, intForReading, False)
Dim objLogFile : Set objLogFile = objFSO.CreateTextFile(strLogFile, True)
Dim strHostname

'Execute nslookup

While Not objInputFile.AtEndOfStream

	strHostname = objInputFile.ReadLine
	If Trim(strHostname) <> "" Then
		Dim objRet : Set objRet = objShell.Exec("%comspec% /c nslookup -type=a -retry=1 -timeout=0 " & strHostname)
		Dim objStdErr : Set objStdErr = objRet.StdErr
		Dim flgFound : flgFound = true
		Do Until objStdErr.AtEndOfStream
			If Left(objStdErr.ReadLine(), 3) = "***" Then
				flgFound = false
				Exit Do
			End If

		Loop
		Dim strIpAddr : strIpAddr = ""
		If flgFound Then
			Dim strLine
			Dim objStdOut : Set objStdOut = objRet.StdOut
			Do Until objStdOut.AtEndOfStream
				strLine = objStdOut.ReadLine()
				If Left(strLine, 7) = "Address" Then
					strIpAddr = Split(strLine, " ")(2)
				End If
			Loop
		End If
	
		'Show result
		'WScript.Echo strIpAddr
		objLogFile.WriteLine(Trim(strHostname)+","+strIpAddr)
	End If
Wend
objInputFile.Close
objLogFile.Close
