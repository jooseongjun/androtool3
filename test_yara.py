import sys, os, yara, subprocess

print ("############## Start YARA Rule!!! ###############")

target = sys.argv[1]

fd_open = subprocess.Popen("pwd",stdout=subprocess.PIPE).stdout
data = fd_open.read().strip()
fd_open.close()

Analysis_path = str(data)
Analysis_path = ((Analysis_path.replace("b'", '')).replace("'", ''))
print (Analysis_path + "/app-release.apk_FILES")

rules = yara.compile(filepath='./result_rule.yar') #Input rule path

for root, dirs, files in os.walk(Analysis_path): #Input analysis path
	for file in files:
		if file.find('.java') >= 0:
			print ("asd")
			print (file)
			target = Analysis_path + file			
			matches = rules.match(target)


			if len(matches.values()) == 0:
				print ("Malware type : ETC")
				pass
			else:
				key = (matches['main'])
				print ("Malware type : %s" %key[0]['rule'])

