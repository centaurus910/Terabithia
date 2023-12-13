import requests
from urllib.parse import urlparse
import re
import json
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from helpers.config import Config
from pathlib import Path

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# only for debugging
burp_proxy = {
    'http': 'http://127.0.0.1:8080',  
    'https': 'http://127.0.0.1:8080'
}


class GetSub:
    def __init__(self, domain, output = False):
        self.domain = domain
        self.outfile = output
        self.subdomains = []
        self.crtsh = []
        self.virustotal = []
        self.securitytrails = []
        self.shodan = []
        self.chaos = []
        self.dnsdumpster = []
        self.facebook_ct = []
        self.cdx = []
        self.hackertarget = []
        self.alienvault = []
        self.logging = []
        self.shodan_api_key = ""
        self.chaos_api_key =""
        self.securitytrails_api_key = ""
        self.config = Config()
        if self.config:
            for secret in self.config.secrets('shodan'):
                self.shodan_api_key = secret
            for secret in self.config.secrets('chaos'):
                self.chaos_api_key = secret
            for secret in self.config.secrets('securitytrails'):
                self.securitytrails_api_key = secret

    #scraping crtsh
    def query_crtsh(self):
        domain = self.domain
        log = self.logging
        crtsh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            data  = requests.get(crtsh_url, verify=False, timeout = 20)
            if data:
                parsed_data = json.loads(data.content)
                for n_value in parsed_data:
                    n_value['name_value'] = n_value['name_value'].strip()
                    if '*' in n_value['name_value']:
                        continue
                    self.subdomains.append(n_value['name_value'])
                    self.crtsh.append(n_value['name_value'])
            else:
                log.append(f"=> [ RESP ] CRTSH response issue: status code is {data.status_code}")
        except Exception as err:
            log.append(f"=> [ EXP ] CRTSH exception error: {err}")

    # scraping virustotal
    def query_virustotal(self):
        domain = self.domain
        log = self.logging
        url = f"https://www.virustotal.com/ui/domains/{domain}/subdomains?relationships=resolutions&cursor=&limit=100"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'X-Vt-Anti-Abuse-Header': 'centaurus',
            'Content-Type': 'application/json',
            'X-Tool': 'vt-ui-main',
            'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            
        try:
            data = requests.get(url, headers=headers, verify = False, timeout=20)
            parsed_data = json.loads(data.content)
            if 'data' in parsed_data.keys():
                for item in parsed_data['data']:
                    if '*' not in item['id']:
                        self.subdomains.append(item['id'])
                        self.virustotal.append(item['id'])
                    else:
                        pass
            else:
                log.append(f"=> [ RESP ] VIRUSTOTAL response issue status code is: {data.status_code}")
                pass
                
        except Exception as err:
            log.append(f"=> [ EXP ] VIRUSTOTAL exception error: {err}")


    #quering securitytrails API
    def query_securitytrails(self):
        log = self.logging
        st_url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains?children_only=false&include_inactive=true"
        apikey = self.securitytrails_api_key
        headers = {
            "apiKey": f"{apikey}",
            "accept": "application/json"
        }

        try:
            data = requests.get(st_url, headers=headers, verify=False)
            parsed_data = json.loads(data.content)
            if parsed_data['subdomain_count']:
                if parsed_data['subdomain_count'] > 0:
                    for subdomain in parsed_data['subdomains']:
                        self.subdomains.append(subdomain+"."+self.domain)
                        self.securitytrails.append(subdomain+"."+self.domain)
            else:
                log.append(f"=> [ RESP ] SECURITYTRAILS response issue status code is {data.status_code}")
        except Exception as err:
            log.append(f"=> [ EXP ] SECURITYTRAILS exception error: {err}")

    #quering shodan
    def query_shodan(self):
        log = self.logging
        domain = self.domain
        API_KEY = self.shodan_api_key
        sdn_url = f"https://api.shodan.io/dns/domain/{domain}?key={API_KEY}"

        try:
            data = requests.get(sdn_url, verify=False)
            parsed_data = json.loads(data.content)
            if 'subdomains' in parsed_data.keys():
                for subdomain in parsed_data['subdomains']:
                    if '*' not in subdomain:
                        self.subdomains.append(subdomain+"."+self.domain)
                        self.shodan.append(subdomain+"."+self.domain)
            else:
                log.append(f"=> [ RESP ] SHODAN response issue status code is: {data.status_code}")
        except Exception as err:
            log.append(f"=> [ EXP ] SHODAN exception error: {err}")


    #query chaos API
    def query_chaos(self):
        log = self.logging
        API_KEY = self.chaos_api_key
        domain = self.domain
        chaos_api_count = f"https://dns.projectdiscovery.io/dns/{domain}"
        chaos_api_subdomains = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {
            "Authorization": f"{API_KEY}" }
        try:
            data_count = requests.get(chaos_api_count, verify=False, headers=headers)
            parsed_data_count = json.loads(data_count.content)
            if parsed_data_count['subdomains'] > 0:
                #print(parsed_data_count['subdomains'])
                data_subdomains = requests.get(chaos_api_subdomains, verify=False, headers=headers)
                parsed_data_subdomains = json.loads(data_subdomains.content)
                if parsed_data_subdomains['subdomains']:
                    for subdomain in parsed_data_subdomains['subdomains']:
                        if '*' not in subdomain:
                            self.subdomains.append(subdomain+"."+domain)
                            self.chaos.append(subdomain+"."+domain)
                else:
                    log.append(f"=> [ RESP ] CHAOS response issue status code is: {data_subdomains.status_code}")
            else:
                pass
        except Exception as err:
            log.append(f"=> [ EXP ] CHAOS exception error: {err}")


    #query dns dumpster
    def query_dnsdumpster(self):
        log = self.logging
        domain = self.domain
        try:
            data = DNSDumpsterAPI().search(domain)
            if data:
                for subdomain in data['dns_records']['host']:
                    if '*' not in subdomain['domain']:
                        self.subdomains.append(subdomain['domain'])
                        self.dnsdumpster.append(subdomain['domain'])
            else:
                log.append(f"=> [ RESP ] DNSDUMPSTER response issue")
        except Exception as err:
            log.append(f"=> [ EXP ] DNSDUMPSTER exception error: {err}")

    #scraping facebook ct
    def query_facebook_ct(self):
        domain = self.domain
        facebook_ct_url = f"https://developers.facebook.com/tools/ct/async/search/?step_size=10000&query={domain}"
        cookies = {
            "c_user":"100066906386646",
            "xs":"44%3ANoH-gnbid_mVSQ%3A2%3A1700218855%3A-1%3A1027%3A%3AAcWpovckeQreIlRHIKBGeSvJQSOKmpOxLLTVRzsgHQ8"
            }
        headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Content-Type":"application/x-www-form-urlencoded",
            "Sec-Fetch-Site":"same-origin"
        }
        post_data = "__usid=6-Ts575j2s1es1y%3APs56gh71jhe1ba%3A0-As575j21r3iopl-RV%3D6%3AF%3D&__user=100066906386646&__a=1&__req=7&__hs=19696.BP%3Adevsite_pkg.2.0..0.0&dpr=1&__ccg=EXCELLENT&__rev=1010207092&__s=9ovo46%3Axuar9k%3A9dk7r0&__hsi=7308970471936421648&__dyn=7xeUmwkHg7ebwKBAo5O12wAxu13wqovzEdEc8uwSwq8S2S0lW4o3Bw5VCwjE3awbG78b87C1xwEw7Bx61vw4iwBgao881FU2IwcK0RE5a1qw8W1uwa-7U1mUdEow46wbS1Lwqo2Ywcq0mW&__csr=&fb_dtsg=NAcP7SbObWN4dCGPYIvRL-QsvjFfSirfMELCcMZ70VyRA3IvQ9Jb_WQ%3A44%3A1700218855&jazoest=25313&lsd=rTzs2d3Fu6wpQvYlioZXDi"
        
        try:
            data = requests.post(facebook_ct_url, verify=False, cookies=cookies, headers=headers, data=post_data, timeout=20)
            #print(data.content) #for debugging
            stripped_data = re.sub(r'^for \(;;\);', '', data.text)
            parsed_data = json.loads(stripped_data)
            for key in parsed_data['payload']['data']:
               for subdomain in key['domains']:
                    if domain in subdomain and '*' not in subdomain:
                        self.subdomains.append(subdomain)
                        self.facebook_ct.append(subdomain)
                    
        except Exception as err:
            print(err)
    
    #scraping google archieves
    def query_cdx(self):
        domain = self.domain
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
        log = self.logging
        try:
            data = requests.get(cdx_url, verify=False, timeout=20)
            parsed_data = json.loads(data.content)
            for url in parsed_data:
                url = url[0].strip()
                parsed_url = urlparse(url)
                subdomain = parsed_url.hostname
                if subdomain != None and '*' not in subdomain:
                    self.subdomains.append(subdomain)
                    self.cdx.append(subdomain)
                else:
                    continue
                
        except Exception as err:
            log.append(f" [ EXP ] CDX exception error: {err}")


    #query hackertarget API
    def query_hackertarget(self):
        log = self.logging
        domain = self.domain
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            data = requests.get(url, verify=False, timeout=20)
            if data.status_code == 200 and domain in data.content.decode('utf-8'):
                decoded_data = data.content.decode('utf-8')
                response_lines = decoded_data.split('\n')
                for line in response_lines:
                    subdomain = line.split(',')[0]
                    if '*' not in subdomain:
                        self.subdomains.append(subdomain)
                        self.hackertarget.append(subdomain)
            else:
                log.append(f"[ RESP ] HackerTarget response issue status code is {data.status_code}")
        except Exception as err:
            log.append(f"[ EXP ] HackerTarget exception error: {err}")
    
    #query alienvault api
    def query_alienvault(self):
        domain = self.domain
        log = self.logging
        alienvault_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            data = requests.get(alienvault_url, verify=False, timeout=20)
            if data.status_code == 200:
                parsed_data = json.loads(data.content)
                if 'error' not in parsed_data.keys() and parsed_data['count'] > 0:
                    sublist = parsed_data['passive_dns']
                    for subdomain in sublist:
                        self.subdomains.append(subdomain['hostname'])
                        self.alienvault.append(subdomain['hostname'])
                else:
                    log.append(f"[ RESP ] Alienvault response issue either count isn't > 0 or no records exist")
            else:
                log.append(f"[ RESP ] Alienvault response issue, unexpected status code: {data.status_code}")
            
        except Exception as err:
            log.append(f"[ EXP ] Alienvault exception error: {err}")
        

    #returning the findings    
    def findings(self):
        final_list = set(self.subdomains)
        return final_list
    
    #Stats
    def stats(self):
        crtsh = self.crtsh
        virustotal = self.virustotal
        securitytrails = self.securitytrails
        shodan = self.shodan
        chaos = self.chaos
        dnsdumpster = self.dnsdumpster
        facebook_ct = self.facebook_ct
        cdx = self.cdx
        hackertarget = self.hackertarget
        alienvault = self.alienvault
        total = self.subdomains

        print("\n\n")
        print("[+] ", len(set(crtsh)), " subdomains found in crt.sh")
        print("[+] ", len(set(virustotal)), " subdomains found in virustotal")
        print("[+] ", len(set(securitytrails)), " subdomains found in securitytrails")
        print("[+] ", len(set(shodan)), " subdomains found in shodan")
        print("[+] ", len(set(chaos)), " subdomains found in chaos")
        print("[+] ", len(set(dnsdumpster)), " subdomains found in dnsdumpster")
        print("[+] ", len(set(facebook_ct)), " subdomains found in facebook CT")
        print("[+] ", len(set(cdx)), " subdomains found in archive.org")
        print("[+] ", len(set(hackertarget)), " subdomains found in hackertarget.com")
        print("[+] ", len(set(alienvault)), " subdomains found in alienvault")
        print("\n")
        print("[+] Terabithia getsub module found ", len(set(total)), "\n")

    #logging
    def report_logs(self):
        logs = self.logging
        print("========= LOGGING =========")
        if len(logs) > 0:
            print("=> [ LOGS ] ",len(logs)," issues were detected")
            for log in logs:
                #print("\n")
                print(log)
        else:
            print("=> No issues were detected")