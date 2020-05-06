<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[

// Hello world
var shell = new ActiveXObject("WScript.Shell");
shell.Popup("Hello world from JScript XSL!");

]]> </ms:script>
</stylesheet>