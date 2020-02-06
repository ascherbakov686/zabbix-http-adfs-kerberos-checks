#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests,os,sys,uuid
from subprocess import Popen, PIPE
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)

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

  try:
    code = requests.get(url, auth=kerberos_auth, allow_redirects=True, verify=False, timeout=30).status_code
  except:
    code = -1

  out = ("- service.%s.status.code %s" % (url.replace("http://","").replace("https://","").replace("/","."), code)).replace("..",".").replace(":","-")

  try:
    with open(tmp,'w') as f: f.write(out)
  except:
    print "Unable to save data to send!"
    sys.exit(1)

  os.system("{0} -s {1}.{2} -z {3} -i {4} -vv".format(sender,node_name,domain,zbx_server,tmp))

  os.remove(tmp)

if __name__ == "__main__":
    kinit()
    main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
