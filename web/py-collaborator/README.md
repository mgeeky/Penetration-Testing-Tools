## py-collaborator - A Python's version of Burp Collaborator (not compatible)
---

This is a client-server piece of software that implements technique discussed by James 'albinowax' Kettle at his [Cracking the Lens](https://portswigger.net/kb/papers/crackingthelens-whitepaper.pdf) whitepaper. 

The tool of trade comes in two flavors:

### 1. Client proxy plugin
---

Implemented for [mitmproxy](https://github.com/mitmproxy/mitmproxy) and for my own [HTTP/S proxy2](https://github.com/mgeeky/proxy2). 


#### mitmproxy

One can use it with **mitmproxy** by loading a script file:

```
$ mitmproxy -s py-collaborator-mitmproxy-addon.py
```

After that, 
- go to your favorite browser
- set up it's proxy so it points on **mitmproxy**'s listening interface and port
- Load up mitmproxy's certificate by browsing to **http://mitm.it** and selecting your option (int Firefox - you can directly go to the: [http://mitm.it/cert/pem](http://mitm.it/cert/pem))
- Select trust checkboxes.

Then, when in **mitmproxy** interface - type in **'E'** to go to Events log and look for following outputs:
```
info: Loading script /mnt/d/dev2/py-collaborator/py-collaborator-mitmproxy-addon.py
info: Initializing py-collaborator-mitmproxy-plugin.
info: Connecting to MySQL database: root@<YOUR-IP> ...
info: Connected.
...
Injected pingbacks for host (d9.sina.com.cn)
info: 127.0.0.1:48162: clientconnect
info: (1) Re-sent misrouted request with hijacked Host header (d9.sina.com.cn -> xxx1yfgeq0a5jrpxb56lycb0w7a7togjpqlrw2pjm2rcqermytibyyyy.<YOUR-HOST>)
info: (2) Re-sent host overriding request (/litong/zhitou/sinaads/test/e-recommendation/release/sinaere.js -> http://xxxqwzmqhx464804woszmnyuhv4idoj9dg83q6aywhcgtjfkq2ewdyyy.<YOUR-HOST>/)
info: (3) Re-sent host header @ manipulated request (d9.sina.com.cn -> d9.sina.com.cn@xxxnd31uvlno1hhpznqxdhhbwp3zsqg2k25nfx5z9q6nku51fgsjnyyy.<YOUR-HOST>)
info: Injected pingbacks for host (d9.sina.com.cn).
...
```

If you spot those lines, the injecting plugin is working and you can now browse your target webapplications. Every request met will get injected headers, as well as there will be couple of additional hand-crafted requests in the background going on. 


#### proxy2

Although **proxy2** is very unstable at the moment, one can give it a try by running:

```
$ ./proxy2.py -p py-collaborator-proxy2-addon.py
```

After that, 
- go to your favorite browser
- set up it's proxy so it points on **proxy2**'s listening interface and port
- Load up proxy2's certificate by browsing to **http://proxy2.test**
- Select trust checkboxes.



### 2. Server part
---

Just as Burp Collaborator needs to listen on ports such as 80, 443, 8080 - our server will need too. In order to handle properly 443/HTTPS traffic, we shall supply to our server wildcard CA certificate, that can be generated using **Let's Encrypt's certbot**. 

- One will need to start a MySQL server, no need to create database or initialize it anyhow.
- Then, we need to configure all needed informations in **config.json** file.
- Having properly filled config.json - we can start up our server:

```
$ python3.7 py-collaborator-server.py
```

Server while running, will handle every **Out-of-band** incoming requests having UUID previously inserted to database, during proxied browsing. Such found correlation will be displayed as follows:

```
hostname|23:55|~/dev/py-collaborator # python3.7 py-collaborator-server.py -d

        :: Cracking the Lens pingback responding server
        Responds to every Out-of-band request correlating them along the way
        Mariusz Banach / mgeeky '16-18, <mb@binary-offensive.com>

[-] You shall specify all needed MySQL connection data either via program options or config file.
[+] Database initialized.
[dbg] Local host's IP address (RHOST) set to:
[+] Serving HTTP server on: ("0.0.0.0", 80)
[+] Serving HTTP server on: ("0.0.0.0", 443)
[+] Serving HTTP server on: ("0.0.0.0", 8080)
[?] Entering infinite serving loop.
[dbg] Incoming HTTP request from <YOUR-IP>:  /


-------------------------------------------------------------------------------------
Issue:                  Pingback (GET / ) found in request's Header: Host
Where payload was put:  Overridden Host header (magnetic.t.domdex.com -> GET /http://xxxkr2hr3nb43pxqb1174wsl48platj701r1d38k7quaf74kukqfqyyy.<YOUR-HOST>:80
Contacting host:        vps3274533.ovh.net
Tried to reach vhost:   xxxkr2hr3nb43pxqb1174wsl48platj701r1d38k7quaf74kukqfqyyy.<YOUR-HOST>:80

Issue detail:
    Our pingback-server was contacted by (<YOUR-IP>:50828) after a delay of (0:03:37.404649):

    Original request where this pingback was inserted:
    ---
        GET /sync/casale HTTP/1.1
        Host: magnetic.t.domdex.com
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0
        Accept: */*
        Accept-Language: pl,en-US;q=0.7,en;q=0.3
        Accept-Encoding: gzip, deflate, br
        Referer: https://ssum-sec.casalemedia.com/usermatch?s=183875&cb=https%3A%2F%2Fpr-bh.ybp.yahoo.com%2Fsync%2Fcasale%2F_UID_
        Connection: keep-alive
        Pragma: no-cache
        Cache-Control: no-cache
        X-Forwarded-For: http://xxxzslzo9p4gig2jxlimfpz3kusjbizg3gj5kylqbupr3ev5pvwdtyyy.<YOUR-HOST>/


    Request that was sent to us in return:
    ---
        GET / HTTP/1.1
        Host: xxxkr2hr3nb43pxqb1174wsl48platj701r1d38k7quaf74kukqfqyyy.<YOUR-HOST>
        User-Agent: curl/7.58.0
        Accept: */*

The payload was sent at (2019-01-13 22:52:40) and received on (2019-01-13 22:56:17).
-------------------------------------------------------------------------------------

```

