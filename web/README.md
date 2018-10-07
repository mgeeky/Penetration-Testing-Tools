## Web Applications penetration testing related scripts, tools and Cheatsheets

- **`ajax_crawl.js`** - AJAX Crawling bookmarklet - useful bookmarklet for fetching accessible, in-scope URLs from the webpage (and it's sitemap.xml) in order to let them be captured in local proxy like Burp. This in turn is useful for populating local proxy's history and it's website resources tree. Must-have during website pentesting. ([gist](https://gist.github.com/mgeeky/db809bec7460707693f2ed3548ea6a43))

- [**`arachni-launching-script`**](https://github.com/mgeeky/arachni-launching-script) - Script intended to make launching of Arachni scanner a little bit more comfortable.

- **`blindxxe.py`** - Blind XXE (External XML Entity) attacker's server - to be used in blind XXE data exfiltration (like in Play Framework or Ruby on Rails). ([gist](https://gist.github.com/mgeeky/7f45c82e8d3097cbbbb250e37bc68573))

- **`blind-xxe-payload-1.txt`** - Simplest Blind XXE Payload to test within HTML request. ([gist](https://gist.github.com/mgeeky/cf677de6e7fdc05803f6935de1ee0882))

- **`burpCookieToUrl.py`** - Example BurpSuite extension copying specified Cookie's value (ticket) into URL parameters set under different name. ([gist](https://gist.github.com/mgeeky/61407112d6d09eaafd542e25590e1d35))

- [**`burpContextAwareFuzzer`**](https://github.com/mgeeky/burpContextAwareFuzzer) - BurpSuite's payload-generation extension aiming at applying fuzzed test-cases depending on the type of payload (basic like integer, string, path; json; GWT; binary) and following encoding-scheme applied.

- **`burp-curl-beautifier.py`** - Simple script for making "Copy as curl command" output in system's clipboard a little nicer, at least for me. ([gist](https://gist.github.com/mgeeky/3a5060e54004ca597241d6752b482675))

- **`create_mitm_certificate.sh`** - Simple SSL/TLS self-signed CA Certificate generator for MITM purposes. ([gist](https://gist.github.com/mgeeky/5e36d6482e73ab85c161c35bfd50c465))

- [**`dirbuster`**](https://github.com/mgeeky/dirbuster) - wfuzz, SecLists and john -based dirbusting / forceful browsing script intended to be used during web pentest assingments.

- **`dummy-web-server.py`** - a minimal http server in python. Responds to GET, HEAD, POST requests, but will fail on anything else. Forked from: [bradmontgomery/dummy-web-server.py](https://gist.github.com/bradmontgomery/2219997) ([gist](https://gist.github.com/mgeeky/c0675b2cf65bad6171edcb8f3bb2af6d))

- **`http-auth-timing.py`** - HTTP Auth Timing attack tool as presented at Ruxcon CTF 2012 simple web challange. The tools tries to use every letter for auth password and construct the entire password upon the longest took authentication request. ([gist](https://gist.github.com/mgeeky/57e866604942f1824da310982c46da84))

- **`java-XMLDecoder-RCE.md`** - Java Beans XMLDecoder XML-deserialization Remote Code Execution payloads. ([gist](https://gist.github.com/mgeeky/5eb48b17c9d282ad3170ef91cfb6fe4c))

- **`pickle-payload.py`** - Python's Pickle Remote Code Execution payload template. ([gist](https://gist.github.com/mgeeky/cbc7017986b2ec3e247aab0b01a9edcd))

- **`struts-cheatsheet.md`** - Apache Struts devMode Remote Code Execution cheatsheet. ([gist](https://gist.github.com/mgeeky/5ba0170a5fd0171eb91bc1fd0f2618b7))
- [**`tomcatWarDeployer`**](https://github.com/mgeeky/tomcatWarDeployer) - Apache Tomcat auto WAR deployment & pwning penetration testing tool.

- **`padding-oracle-tests.py`** - Padding Oracle test-cases generator utility aiding process of manual inspection of cryptosystem's responses. ([gist](https://gist.github.com/mgeeky/5dfa475af2c970197a62ad070ba5deee))

```
#   Simple utility that aids the penetration tester when manually testing Padding Oracle condition
#   of a target cryptosystem, by generating set of test cases to fed the cryptosystem with.
#
# Script that takes from input an encoded cipher text, tries to detect applied encoding, decodes the cipher
# and then generates all the possible, reasonable cipher text transformations to be used while manually
# testing for Padding Oracle condition of cryptosystem. The output of this script will be hundreds of
# encoded values to be used in manual application testing approaches, like sending requests.
#
# One of possible scenarios and ways to use the below script could be the following:
#   - clone the following repo: https://github.com/GDSSecurity/PaddingOracleDemos
#   - launch pador.py which is an example of application vulnerable to Padding Oracle
#   - then by using `curl http://localhost:5000/echo?cipher=<ciphertext>` we are going to manually
#       test for Padding Oracle outcomes. The case of returning something not being a 'decryption error'
#       result would be considered padding-hit, therefore vulnerability proof.
#
#   This script could be then launched to generate every possible test case of second to the last block
#   being filled with specially tailored values (like vector of zeros with last byte ranging from 0-255)
#   and then used in some kind of local http proxy (burp/zap) or http client like (curl/wget).
```

- **`post.php`** - (GIST discontinued, for recent version check: https://github.com/mgeeky/PhishingPost ) PHP Credentials Harversting script to be used during Social Engineering Phishing campaigns/projects. ([gist](https://gist.github.com/mgeeky/32375178621a5920e8c810d2d7e3b2e5))

- **`reencode.py`** - ReEncoder.py - script allowing for recursive encoding detection, decoding and then re-encoding. To be used for instance in fuzzing purposes. Imagine you want to fuzz XML parameters within **PaReq** packet of 3DSecure standard. This packet has been ZLIB compressed, then Base64 encoded, then URLEncoded. In order to modify the inner XML you would need to peel off that encoding layers and then reaplly them in reversed order. This script allows you to do that in an automated manner. ([gist](https://gist.github.com/mgeeky/1052681318a8164b112edfcdcb30798f))

    Sample output could look like:

```
Usage: detect.py <text>
Using sample: "4a5451344a5459314a545a6a4a545a6a4a545a6d4a5449774a5463334a545a6d4a5463794a545a6a4a5459304a5449784a5449774a544e684a544a6b4a544935"
[+] Detected encoding: HexEncoded
[+] Detected encoding: Base64
[+] Detected encoding: URLEncoder
[.] No more encodings.
[.] Input data encoded according to: ['HexEncoded', 'Base64', 'URLEncoder']
[>] Decoding HexEncoded: (4a5451344a5459314a545a6a4a545a6a4a545a6d4a5449774a5463334a545a6d4a5463794a545a6a4a5459304a5449784a5449774a544e684a544a6b4a544935) => (JTQ4JTY1JTZjJTZjJTZmJTIwJTc3JTZmJTcyJTZjJTY0JTIxJTIwJTNhJTJkJTI5)
[>] Decoding Base64: (JTQ4JTY1JTZjJTZjJTZmJTIwJTc3JTZmJTcyJTZjJTY0JTIxJTIwJTNhJTJkJTI5) => (%48%65%6c%6c%6f%20%77%6f%72%6c%64%21%20%3a%2d%29)
[>] Decoding URLEncoder: (%48%65%6c%6c%6f%20%77%6f%72%6c%64%21%20%3a%2d%29) => (Hello world! :-))
(1) DECODED TEXT: "Hello world! :-)"

(2) TO BE ENCODED TEXT: "FOO Hello world! :-) BAR"
[>] Encoding URLEncoder: (FOO Hello world! :-) BAR) => (FOO%20Hello%20world%21%20%3A-%29%20BAR)
[>] Encoding Base64: (FOO%20Hello%20world%21%20%3A-%29%20BAR) => (Rk9PJTIwSGVsbG8lMjB3b3JsZCUyMSUyMCUzQS0lMjklMjBCQVI=)

[>] Encoding HexEncoded: (Rk9PJTIwSGVsbG8lMjB3b3JsZCUyMSUyMCUzQS0lMjklMjBCQVI=) => (526b39504a544977534756736247386c4d6a423362334a735a4355794d5355794d43557a5153306c4d6a6b6c4d6a42435156493d)
(3) ENCODED FORM: "526b39504a544977534756736247386c4d6a423362334a735a4355794d5355794d43557a5153306c4d6a6b6c4d6a42435156493d"
```

When `DEBUG` is turned on, the output may also look like:

```
$ ./reencode.py JTQxJTQxJTQxJTQx
[.] Trying: URLEncoder (peeled off: 0). Current form: "JTQxJTQxJTQxJTQx"
[.] Trying: HexEncoded (peeled off: 0). Current form: "JTQxJTQxJTQxJTQx"
[.] Trying: Base64 (peeled off: 0). Current form: "JTQxJTQxJTQxJTQx"
[.] Unclear situation whether input (JTQxJTQxJTQxJTQx) is Base64 encoded. Branching.
[*] Generator returned: ("None", "JTQxJTQxJTQxJTQx", True)
[+] Detected encoder: Base64
[*] Generator returned: ("Base64", "%41%41%41%41", False)
[.] Trying: URLEncoder (peeled off: 1). Current form: "%41%41%41%41"
[+] Detected encoder: URLEncoder
[*] Generator returned: ("URLEncoder", "AAAA", False)
[.] Trying: URLEncoder (peeled off: 2). Current form: "AAAA"
[.] Trying: HexEncoded (peeled off: 2). Current form: "AAAA"
[.] Unclear situation whether input (AAAA) is Hex encoded. Branching.
[*] Generator returned: ("None", "AAAA", True)
[+] Detected encoder: HexEncoded
[*] Generator returned: ("HexEncoded", "��", False)
[.] Trying: URLEncoder (peeled off: 3). Current form: "��"
[.] Trying: HexEncoded (peeled off: 3). Current form: "��"
[.] Trying: Base64 (peeled off: 3). Current form: "��"
[.] Trying: Base64URLSafe (peeled off: 3). Current form: "��"
[.] Trying: JWT (peeled off: 3). Current form: "��"
[.] Trying: None (peeled off: 3). Current form: "��"
None (JTQxJTQxJTQxJTQx)
├── None (JTQxJTQxJTQxJTQx)
└── Base64 (%41%41%41%41)
    └── URLEncoder (AAAA)
        ├── None (AAAA)
        └── HexEncoded ()
[.] Candidate for best decode using None: "AAAA"...
[.] Candidate for best decode using HexEncoded: "��"...
[=] Evaluating candidate: None (data: AAAA)
	Adding 10.0 points for printable characters.
	Adding 0.0 points for high entropy.
	Adding 4.0 points for length.
	Scored in total: 14.0 points.
[=] Evaluating candidate: HexEncoded (data: ��)
	Adding 0.0 points for printable characters.
	Adding 0.0 points for high entropy.
	Adding 2.0 points for length.
	Scored in total: 2.0 points.
[?] Other equally good candidate paths:
(Node('/None/Base64/URLEncoder', decoded='AAAA'), Node('/None/Base64/URLEncoder/None', decoded='AAAA'))
[+] Winning decode path is:
Node('/None/Base64/URLEncoder', decoded='AAAA')
[+] Selected encodings: ['None', 'Base64', 'URLEncoder']
(1) DECODED TEXT: "AAAA"

(2) TO BE ENCODED TEXT: "FOO AAAA BAR"
(3) ENCODED FORM: "Rk9PJTIwQUFBQSUyMEJBUg=="
```

- **`sqlmap-tamper-scripts-evaluation.md`** - Results of my evaluation of **sqlmap**'s tamper scripts against detectability and rating used in F5 Big-IP ASM WAF.

- **`oRTC-leak-internal-ip.js`** - Internal IP address leakage via Object RTC (ORTC) interface implemented in Microsoft Edge. ([gist](https://gist.github.com/mgeeky/03f0871fb88c64b3d6d3a725c3ba38bf))


- **`xml-attacks.md`** - XML Vulnerabilities and Attacks cheatsheet. ([gist](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870))

- **`XXE Payloads`** - Internal IP address leakage via Object RTC (ORTC) interface implemented in Microsoft Edge. ([gist](https://gist.github.com/mgeeky/181c6836488e35fcbf70290a048cd51d))

- **`ysoserial-generator.py`** - This tool helps fuzzing applications that use Java serialization under the hood, by automating `ysoserial` proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. 
This tool generates every possible payload for every implemented gadget, thus resulting in number of payload files (or one file with number of lines), being URL/Base64 encoded along the way or not - which can be later used for manual penetration testing assignments like pasting that file to BurpSuite intruder, or enumerating every payload from within bash/python script.


