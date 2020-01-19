## malleable-redirector - a proxy2 plugin

**Let's raise the bar in C2 redirectors IR resiliency, shall we?**

Red Teaming business has seen [several](https://bluescreenofjeff.com/2016-04-12-combatting-incident-responders-with-apache-mod_rewrite/) [different](https://posts.specterops.io/automating-apache-mod-rewrite-and-cobalt-strike-malleable-c2-profiles-d45266ca642) [great](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10) ideas on how to combat incident responders and misdirect them while offering resistant C2 redirectors network at the same time.  

This piece of code tries to combine many of these great ideas into a one, lightweight utility, mimicking Apache2 in it's roots of being a simple HTTP(S) reverse-proxy. Combining Malleable C2 profiles understanding, knowledge of bad IP addresses pool and a flexibility of easily adding new inspection and misrouting logc - resulted in having a crafty repellent for IR evasion. 

### Abstract

This program acts as a HTTP/HTTPS reverse-proxy with several restrictions imposed upon which requests and from whom it should process, similarly to the .htaccess file in Apache2's mod_rewrite.

`malleable_redirector` was created to resolve the problem of effective IR/AV/EDRs/Sandboxes evasion on the C2 redirector's backyard. It comes in a form of a plugin for other project of mine called [proxy2](https://github.com/mgeeky/proxy2), that is a lightweight forward & reverse HTTP/HTTPS proxy.

The proxy2 in companion with this plugin can act as a CobaltStrike Teamserver C2 redirector, given Malleable C2 profile used during the campaign and teamserver's hostname:port. The plugin will parse supplied malleable profile in order to understand which inbound requests may possibly come from the compatible Beacon or are not compliant with the profile and therefore should be misdirected. Sections such as http-stager, http-get, http-post and their corresponding uris, headers, prepend/append patterns, User-Agent are all used to distinguish between legitimate beacon's request and some Internet noise or IR/AV/EDRs out of bound inquiries. 

The plugin was also equipped with marvelous known bad IP ranges coming from:
  curi0usJack and the others:
  [https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10)

Using an IP addresses blacklisting along with known bad keywords lookup through Reverse-IP DNS queries and HTTP headers, the reliability of this tool results considerably increased redirector's resiliency to the unauthorized peers wanting to examine protected infrastructure.

Use wisely, stay safe.

### Example usage

```
$ python3 proxy2.py -P 80/http -P 443/https -p plugins/malleable_redirector.py --profile jquery-c2.3.14.profile --teamserver-url 1.2.3.4:8080 -v

  [INFO] 19:21:42: Loading 1 plugin...
  [INFO] 19:21:42: Plugin "malleable_redirector" has been installed.
  [INFO] 19:21:42: Preparing SSL certificates and keys for https traffic interception...
  [INFO] 19:21:42: Using provided CA key file: ca-cert/ca.key
  [INFO] 19:21:42: Using provided CA certificate file: ca-cert/ca.crt
  [INFO] 19:21:42: Using provided Certificate key: ca-cert/cert.key
  [INFO] 19:21:42: Serving http proxy on: 0.0.0.0, port: 80...
  [INFO] 19:21:42: Serving https proxy on: 0.0.0.0, port: 443...
  [INFO] 19:21:42: [REQUEST] GET /jquery-3.3.1.min.js
  [INFO] 19:21:42: == Valid malleable http-get request inbound.
  [INFO] 19:21:42: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
  [INFO] 19:21:42: [RESPONSE] HTTP 200 OK, length: 5543
  [INFO] 19:21:45: [REQUEST] GET /jquery-3.3.1.min.js
  [INFO] 19:21:45: == Valid malleable http-get request inbound.
  [INFO] 19:21:45: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
  [INFO] 19:21:45: [RESPONSE] HTTP 200 OK, length: 5543
  [INFO] 19:21:46: [REQUEST] GET /
  [...]
  [ERROR] 19:24:46: [DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
  [...]
  [INFO] 19:24:46: [RESPONSE] HTTP 301 Moved Permanently, length: 212
  [INFO] 19:24:48: [REQUEST] GET /jquery-3.3.1.min.js
  [INFO] 19:24:48: == Valid malleable http-get request inbound.
  [INFO] 19:24:48: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
  [...]
```

The above output contains a line pointing out that there has been an unauthorized, not compliant with our C2 profile inbound request, which got dropped due to incompatible User-Agent string presented:
```
  [...]
  [DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
  [...]
```

### TODO:

- Add some unique beacons tracking logic to offer flexilibity of refusing staging and communication processes at the proxy's own discretion
- Introduce day of time constraint when offering redirection capabilities
- Keep track of metadata/ID payloads to better distinguish connecting peers and avoid replay attack consequences
- Test it thoroughly with several enterprise-grade EDRs, Sandboxes and others 
- Add Proxy authentication and authorization logic on CONNECT/relay.
- Add Mobile users targeted redirection

### Author

Mariusz B. / mgeeky, '20
<mb@binary-offensive.com>

