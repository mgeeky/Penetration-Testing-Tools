#!/usr/bin/python

from burp import IBurpExtender
from burp import IParameter
from burp import IHttpListener
from burp import IExtensionStateListener

# Can be used with:
#   https://github.com/securityMB/burp-exceptions
# from exceptions_fix import FixBurpExceptions
import sys
import re
import urlparse
from urllib import urlencode


HOST_SCOPE = 'www.example.com'
TRIGGER_PATTERN = '/some/path/'
COOKIE_NAME = 'cookieTicket'
PARAMETER_NAME = 'ticket'

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    ticket = ''

    def registerExtenderCallbacks(self, callbacks):  
        # sys.stdout = callbacks.getStdout()

        print '[+] Ticket appender is loading...'

        self._callbacks = callbacks

        # helpers object for analyzing HTTP request
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Copy Specific Cookie into URL parameter")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        return

    def addUrlParam(self, _url, name, value):
        pos1 = _url.find(' ') + 1
        pos2 = _url.rfind(' ')
        url = _url[pos1:pos2]

        url_parts = list(urlparse.urlparse(url))
        query = dict(urlparse.parse_qsl(url_parts[4]))
        query.update({name : value})
        url_parts[4] = urlencode(query)

        new_url = str(urlparse.urlunparse(url_parts))

        return _url[:pos1] + new_url + _url[pos2:]


    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if messageIsRequest:
            requestInfo = self._helpers.analyzeRequest(currentRequest)

            headers = requestInfo.getHeaders()

            if re.match('Host: ' + HOST_SCOPE, headers[1], re.I):
                for h in headers:
                    if 'Cookie' in h and COOKIE_NAME in h:
                        pos0 = h.find(COOKIE_NAME)
                        pos1 = h.find('=', pos0)
                        pos2 = h.find(';', pos1)
                        ticket = h[pos1+1:pos2]

                        if ticket != self.ticket:
                            print "[?] Cookie's value changed: '%s' => '%s'" % (ticket, self.ticket)
                            self.ticket = ticket

                url = headers[0]
                print '[*] Working url: "%s"' % url
                print '[*] Self.ticket = "%s"' % self.ticket

                if TRIGGER_PATTERN in url and self.ticket != '' and PARAMETER_NAME + '=' not in url:
                    print '[?] No Ticket parameter in URL. Adding it...'

                    newHeaders = list(headers)
                    newHeaders[0] = self.addUrlParam(url, PARAMETER_NAME, ' ' + self.ticket)
                    print '[?] Updating URL from: "%s" => "%s"' % (headers[0], newHeaders[0])

                    bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
                    bodyStr = self._helpers.bytesToString(bodyBytes)

                    newMessage = self._helpers.buildHttpMessage(newHeaders, bodyStr)
                    currentRequest.setRequest(newMessage)

# FixBurpExceptions()