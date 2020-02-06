#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import logging
import sys
import urllib
import urllib2 as u2
import cookielib
import HTMLParser
#import kerberos as k
#import gssapi as k
import urllib_gssapi
import os,uuid
from subprocess import Popen, PIPE

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

def getLogger():
    log = logging.getLogger("http_negotiate_auth_handler")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log

log = getLogger()

class HTTPNegotiateAuthHandler(u2.BaseHandler):

    rx = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
    handler_order = 480  # before Digest auth

    def negotiate_value(self, headers):
        authreq = headers.get('www-authenticate', None)

        if authreq:
            mo = HTTPNegotiateAuthHandler.rx.search(authreq)
            if mo:
               return mo.group(1)
            else:
               log.debug("regex failed on: %s" % authreq)

        else:
            log.debug("www-authenticate header not found")

        return None

    def __init__(self):
        self.retried = 0
        self.context = None

    def generate_request_header(self, req, headers):
        neg_value = self.negotiate_value(headers)
        if neg_value is None:
            self.retried = 0
            return None

        if self.retried > 5:
            raise HTTPError(req.get_full_url(), 401, "negotiate auth failed",
                            headers, None)

        self.retried += 1

        log.debug("req.get_host() returned %s" % req.get_host())
        result, self.context = k.authGSSClientInit("HTTP@%s" % req.get_host())

        if result < 1:
            log.warning("authGSSClientInit returned result %d" % result)
            return None

        log.debug("authGSSClientInit() succeeded")

        result = k.authGSSClientStep(self.context, neg_value)

        if result < 0:
            log.warning("authGSSClientStep returned result %d" % result)
            return None

        log.debug("authGSSClientStep() succeeded")

        response = k.authGSSClientResponse(self.context)
        log.debug("authGSSClientResponse() succeeded")

        return "Negotiate %s" % response

    def authenticate_server(self, headers):
        neg_value = self.negotiate_value(headers)
        if neg_value is None:
            log.debug("mutual auth failed. No negotiate header")
            return None

        if k.authGSSClientStep(self.context, neg_value) < 1:
            log.debug("mutual auth failed: authGSSClientStep returned result %d" % result)

    def clean_context(self):
        if self.context is not None:
            k.authGSSClientClean(self.context)

    def http_error_401(self, req, fp, code, msg, headers):
        log.debug("inside http_error_401")
        try:
            neg_hdr = self.generate_request_header(req, headers)

            if neg_hdr is None:
                log.debug("neg_hdr was None")
                return None

            req.add_unredirected_header('Authorization', neg_hdr)
            resp = self.parent.open(req)

            self.authenticate_server(resp.info())

            return resp

        finally:
            self.clean_context()


class Client:
  def __init__(self):
    cj = cookielib.CookieJar()
    self.opener = u2.build_opener(u2.HTTPCookieProcessor(cj))
    #self.opener.add_handler(HTTPNegotiateAuthHandler())
    self.opener.add_handler(urllib_gssapi.HTTPSPNEGOAuthHandler())

  def get(self, url):
    res = self.opener.open(url,timeout=30)

    if res.geturl() == url:
      return res

    auth_url  = res.geturl()

    res = self.opener.open(auth_url,timeout=30)

    content = res.read()

    # debug
    #print content

    html_parser = HTMLParser.HTMLParser()

    assertion_url_regex = re.compile('<form method="POST" name="hiddenform" action="(.*?)">')
    relay_state_regex   = re.compile('<input type="hidden" name="RelayState" value="(.*?)" />')
    saml_response_regex = re.compile('<input type="hidden" name="SAMLResponse" value="(.*?)" />')

    assertion_url_match = assertion_url_regex.search(content)
    relay_state_match   = relay_state_regex.search(content)
    saml_response_match = saml_response_regex.search(content)

    assertion_url       = html_parser.unescape(assertion_url_match.group(1))
    relay_state         = html_parser.unescape(relay_state_match.group(1))
    saml_response       = saml_response_match.group(1)

    saml_data = urllib.urlencode({
      'RelayState': relay_state,
      'SAMLResponse': saml_response
    })

    return self.opener.open(assertion_url, saml_data, timeout=30)

def kinit():
    kinit = Popen(['kinit', 'svc_zbxmon@DOMAIN.RU'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    pwd = open('/etc/zabbix/secret', 'r').read()
    kinit.stdin.write('%s\n' % pwd)
    kinit.wait()

def main(url='',domain='',zbx_server='',node_name=''):
    unique = uuid.uuid1()
    sender = '/usr/bin/zabbix_sender'
    tmp = "/tmp/http_check_stats_%s.tmp" % (unique)
    out = ''
    code = -1

    client = Client()

    try:
       code = client.get(url).code
    except:
       code = -1

    out = ("- service.%s.status.code %s" % (url.replace("http://","").replace("https://","").replace("/","."), code)).replace("..",".").replace(":","-")

    #print out

    try:
      with open(tmp,'w') as f: f.write(out)
    except:
      print "Unable to save data to send!"
      sys.exit(1)

    os.system("{0} -s {1}.{2} -z {3} -i {4}".format(sender,node_name,domain,zbx_server,tmp))

    os.remove(tmp)



if __name__ == "__main__":
    kinit()
    main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])

