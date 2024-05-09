#! /usr/bin/env python3

#import re
import requests
import json
import DNS
import re


import subprocess
import spf


CHECK_PASS=0
CHECK_FAIL=1



class DKIMChecker:
    def __init__(self):
        self.signing_domains = dict()
        line_matcher = re.compile('(?P<domain>\S+)\s+(?P<record>\S+)')   
        with open('/etc/opendkim/SigningTable', 'r') as f:
            for line in f:
                match = line_matcher.match(line.strip())
                if match is None:
                    raise ValueError('Failed to initialise Signing Table')
                self.signing_domains[match['domain']] = match['record']                    

    def check(self, domain):
        if domain not in self.signing_domains:
            return [CHECK_FAIL, 'Domain {domain} not in signing table'.format(domain=domain)]
        record = self.signing_domains[domain]
        try:
            r = DNS.dnslookup(name=record, qtype='txt')
        except DNS.Base.ServerError:
            return [CHECK_FAIL, 'DKIM record lookup failed']
        return [CHECK_PASS, '']                    
    
class SPFChecker:

    def check(self, domain):
        get_ip_endpoint='https://ipinfo.io/json'

        response = requests.get(get_ip_endpoint, verify=True)
        if response.status_code != 200:
            return [CHECK_FAIL,'failed to find IP for this host - failed to decode response']
        data = response.json() 
        if 'ip' not in data:
            return [CHECK_FAIL, 'failed to find IP for this host - failed to decode response']
        my_ip = data['ip']
                
        result = spf.check2(i=my_ip,
                            s='{username}@{domain}'.format(username='admin',domain=domain),
                            h='fuzion.co.nz')        
        if result[0] != 'pass':
            return [CHECK_FAIL, 'SPF Failed: {reason}'.format(reason=' '.join(result))]
        return [CHECK_PASS, '']

def main():
    spfchecker = SPFChecker()
    dkimchecker = DKIMChecker()
    checks = [spfchecker, dkimchecker]
    
    result = subprocess.run(['./get_sending_email_domains.sh'], stdout=subprocess.PIPE)
    failures = {}
    for domain in result.stdout.decode('utf-8').strip().split('\n'):
        failures[domain] = [msg for check_status, msg in [check.check(domain) for check in checks] if check_status != CHECK_PASS]


    for domain in failures:
        for failure in failures[domain]:
            print(domain + ' ' + failure)
              
    
if __name__ == '__main__':
    main()


        
    
    
