#/bin/bash
# Written by Samuel Johnson
# Inspired from Girish Bhai's 'level-2-useful-commands'
# auto-check-compliance.sh: Script to automatically check compliance w.r.t CSMD
# Requires: nmap, curl and dig. All tests are carried out from local system.

if [ $# -ne 2 ]
then
    echo "Usage: $0 <host> <port>"
    exit
fi

host=$1
port=$2

date=`date +'%Y-%m-%d:%H:%M:%S'`

# Print the third part of domain as Centre/Unit dff
echo -n "Centre/Unit Name: "
centre=`echo $host | rev | awk -F'.' '{print $3}' | rev | awk '{print toupper($0)}'`
echo $centre

mkdir -p logs/$centre
mkdir -p reports/$centre

domain=`echo $host | rev | awk -F'.' '{print $1"."$2"."$3}' | rev`

# Recon and collect data
echo "Performing recon"

echo -n 'Performing Port Scan... '
nmap -Pn $host > logs/$centre/$host.nmap.$date.txt
echo 'done'

echo -n 'Getting HTTP Methods... '
nmap -p $port $host --script http-methods --script-args http.useragent="Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0" > logs/$centre/$host.http-methods.$date.txt
echo 'done'

echo -n 'Downloading Headers.... '

if [ $port = 443 ];
then
	curl -s -i -L -I https://$host > logs/$centre/$host.curl.$date.txt -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
else
	curl -s -i -L -I http://$host:$port > logs/$centre/$host.curl.$date.txt -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
fi

echo done

if [ $port = 443 ]; then
	echo ''
	echo 'TLS Supported, performing additional scans'
	echo -n 'Enumerating all supported TLS ciphers... '
	nmap --script ssl-enum-ciphers -p $port $host > logs/$centre/$host.tls-support.$date.txt
	echo done
	
	echo -n 'Testing Poodle...'
	nmap --script ssl-poodle.nse   -p $port $host > logs/$centre/$host.tls-poodle.$date.txt
	echo done
	
	echo -n 'Testing Logjam...'
	nmap --script ssl-dh-params    -p $port $host > logs/$centre/$host.tls-logjam.$date.txt
	echo done
	
	echo -n 'Testing Heartbleed...'
	nmap --script ssl-heartbleed   -p $port $host > logs/$centre/$host.tls-heartbleed.$date.txt
	echo done
	
	echo -n 'Testing DROWN...'
	nmap --script sslv2-drown      -p $port $host > logs/$centre/$host.tls-drown.$date.txt
	echo done
	
	echo -n 'Testing CRIME...'
	curl -s -I -H 'Accept-Encoding: gzip,deflate' https://$host > logs/$centre/$host.tls-crime.$date.txt -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
	echo done
	
	echo -n 'Testing CCS Injection...'
	nmap --script ssl-ccs-injection -p $port $host > logs/$centre/$host.tls-ccs-injection.$date.txt
	echo done
	
	echo -n 'Testing Anonymous Ciphers...'
	openssl s_client -cipher aNULL -connect $host:$port > logs/$centre/$host-tls-anon.$date.txt 2>&1
	echo done
	
	echo -n 'Testing DNS CAA record...'
	dig @1.0.0.1 CAA $host +short > logs/$centre/$host.dns-caa-host.$date.txt
	dig @1.0.0.1 CAA $domain +short > logs/$centre/$host.dns-caa-domain.$date.txt
	echo done
fi

echo 'Recon Completed'
echo ''
## Recon done


echo -n 'Generating report '

echo -n "Centre/Unit Name: " > reports/$centre/report.$host.$date.txt
echo $host | rev | awk -F'.' '{print $3}' | rev | awk '{print toupper($0)}' >> reports/$centre/report.$host.$date.txt

echo -n 'Host: ' >> reports/$centre/report.$host.$date.txt
echo $host >> reports/$centre/report.$host.$date.txt
echo ''

# 1. Port 80 and 443 are only open on the web server
# Perform port scan to determine
echo '1. Port 80 and 443 are only open on the web server:' >> reports/$centre/report.$host.$date.txt
echo 'Ports identified on the host:' >> reports/$centre/report.$host.$date.txt
grep '[0-9]/' logs/$centre/$host.nmap.$date.txt >> reports/$centre/report.$host.$date.txt


# 2. Website is operational over http only
# If the port TCP/443 is listening, then no
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '2. Website is operational over http only: ' >> reports/$centre/report.$host.$date.txt
if grep 443 logs/$centre/$host.nmap.$date.txt > /dev/null
then
	echo 'No' >> reports/$centre/report.$host.$date.txt
else
	echo 'yes' >> reports/$centre/report.$host.$date.txt
fi


# 3. Website is operational over https only
# If the port TCP/80 is listening, then no
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '3. Website is operational over https only: ' >> reports/$centre/report.$host.$date.txt
if grep 80 logs/$centre/$host.nmap.$date.txt > /dev/null
then
	echo 'No' >> reports/$centre/report.$host.$date.txt
else
	echo 'Yes' >> reports/$centre/report.$host.$date.txt
fi


# 4. Is existing live Website audited by CERT-In authorized empanelled security auditor?
# Cannot be automated, to the best of my knowledge
echo '' >> reports/$centre/report.$host.$date.txt
echo '4. Is existing live Website audited by CERT-In authorized empanelled security auditor? ' >> reports/$centre/report.$host.$date.txt
echo 'Please check with the Centre/Unit.' >> reports/$centre/report.$host.$date.txt


# 5. Header: Webserver version display is disabled
# Check the Server: header
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '5. Header: Webserver version display is disabled: ' >> reports/$centre/report.$host.$date.txt
if grep -i ^Server logs/$centre/$host.curl.$date.txt > /dev/null
then
	echo -n 'No, ' >> reports/$centre/report.$host.$date.txt
	grep -i ^Server logs/$centre/$host.curl.$date.txt >> reports/$centre/report.$host.$date.txt
else
	echo 'Yes' >> reports/$centre/report.$host.$date.txt
fi

# 6. Header: PHP/CMS/Other software version display is disabled
# Perform a dictionary lookup of known CMS names in header
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '6. Header: PHP/CMS/Other software version display is disabled: ' >> reports/$centre/report.$host.$date.txt
while read line; do (if grep -i $line logs/$centre/$host.curl.$date.txt > /dev/null;then echo $line; else continue; fi); done < res/cms.txt >> reports/$centre/report.$host.$date.txt
echo '' >> reports/$centre/report.$host.$date.txt


# 7. Header: E-tag is disabled
# Check the Etag: header
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '7. Header: E-tag is disabled: ' >> reports/$centre/report.$host.$date.txt
if grep -i ^ETag logs/$centre/$host.curl.$date.txt > /dev/null
then
	echo -n 'No, ' >> reports/$centre/report.$host.$date.txt
	grep -i ^ETag logs/$centre/$host.curl.$date.txt >> reports/$centre/report.$host.$date.txt
else
	echo 'Yes' >> reports/$centre/report.$host.$date.txt
fi


# 8. Header: X-XSS-Protection is enabled
# Check the X-XSS-Protection: header
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '8. Header: X-XSS-Protection is enabled: ' >> reports/$centre/report.$host.$date.txt
if grep -i ^X-XSS-Protection logs/$centre/$host.curl.$date.txt > /dev/null
then
	echo -n 'Yes, ' >> reports/$centre/report.$host.$date.txt
	grep -i -m1 ^X-XSS-Protection logs/$centre/$host.curl.$date.txt >> reports/$centre/report.$host.$date.txt
else
	echo 'No' >> reports/$centre/report.$host.$date.txt
fi


# 9. Header: X-Frame-Options is enabled
# Check the X-Frame-Options: header
echo '' >> reports/$centre/report.$host.$date.txt
echo -n '9. Header: X-Frame-Options is enabled: ' >> reports/$centre/report.$host.$date.txt
if grep -i ^X-Frame-Options logs/$centre/$host.curl.$date.txt > /dev/null
then
	echo -n 'Yes, ' >> reports/$centre/report.$host.$date.txt
	grep -i -m1 ^X-Frame-Options logs/$centre/$host.curl.$date.txt >> reports/$centre/report.$host.$date.txt
else
	echo 'No' >> reports/$centre/report.$host.$date.txt
fi


# 10. Header: Strict-Transport-Security is enabled
# Check the Strict-Transport-Security:  header
echo '' >> reports/$centre/report.$host.$date.txt
echo '10. Header: Strict-Transport-Security is enabled: ' >> reports/$centre/report.$host.$date.txt
if grep -i ^Strict-Transport-Security logs/$centre/$host.curl.$date.txt > /dev/null
then
	echo -n 'Yes, ' >> reports/$centre/report.$host.$date.txt
	grep -i -m1 ^Strict-Transport-Security logs/$centre/$host.curl.$date.txt >> reports/$centre/report.$host.$date.txt
else
	echo 'No' >> reports/$centre/report.$host.$date.txt
fi

# 11. Header: Content-Security-Policy is enabled
# Check the Content-Security-Policy: header
echo '' >> reports/$centre/report.$host.$date.txt
echo '11. Header: Content-Security-Policy is enabled: ' >> reports/$centre/report.$host.$date.txt
if grep -i ^Content-Security-Policy logs/$centre/$host.curl.$date.txt > /dev/null
then
	echo -n 'Yes, ' >> reports/$centre/report.$host.$date.txt
	grep -i -m1 ^Content-Security-Policy logs/$centre/$host.curl.$date.txt >> reports/$centre/report.$host.$date.txt
else
	echo 'No' >> reports/$centre/report.$host.$date.txt
fi


# 12. Header: Cookies is set as HttpOnly and Secure
# Check the Set-Cookie: header
echo '' >> reports/$centre/report.$host.$date.txt
echo '12. Header: Cookies is set as HttpOnly and Secure: ' >> reports/$centre/report.$host.$date.txt
if grep -i Set-Cookie logs/$centre/$host.curl.$date.txt | grep -i secure | grep -i httponly > /dev/null
then
	echo -n 'Yes, ' >> reports/$centre/report.$host.$date.txt
	grep -i Set-Cookie logs/$centre/$host.curl.$date.txt | grep -i secure | grep -i httponly >> reports/$centre/report.$host.$date.txt
else
	echo 'No' >> reports/$centre/report.$host.$date.txt
fi

# 13. HTTP Methods like PUT, TRACE, DELETE, OPTION, TRACE are disabled, unless needed
# Check the nmap report
echo '' >> reports/$centre/report.$host.$date.txt
echo '13. HTTP Methods like PUT, TRACE, DELETE, OPTION, TRACE are disabled, unless needed: ' >> reports/$centre/report.$host.$date.txt
grep 'Supported Methods' logs/$centre/$host.http-methods.$date.txt >> reports/$centre/report.$host.$date.txt


# 14. Remote Login of CMS or Site Management or Tomcat Manager is not accessible over Internet
# Has to be manually check using dirb or by other means
echo '' >> reports/$centre/report.$host.$date.txt
echo '14. Remote Login of CMS or Site Management or Tomcat Manager is not accessible over Internet: ' >> reports/$centre/report.$host.$date.txt
echo Use tools like dirb or perform manual testing >> reports/$centre/report.$host.$date.txt

if [ $port = 443 ]; then
	# 15. TLSv 1.0, SSLv2, SSLv3 support is disabled
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '15. TLSv 1.0, SSLv2, SSLv3 support is disabled: ' >> reports/$centre/report.$host.$date.txt
	if grep 'SSLv2\|SSLv3\|TLSv1.0' logs/$centre/$host.tls-support.$date.txt > /dev/null
	then
		echo -n 'No, ' >> reports/$centre/report.$host.$date.txt
		grep 'SSLv2\|SSLv3\|TLSv1.0' logs/$centre/$host.tls-support.$date.txt >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 16. Weak Cipher support over secure communication is disabled
	# If the least strength as reported by nmap is not A, then probaly weak ciphers are supported. Check the nmap report
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '16. Weak Cipher support over secure communication is disabled: ' >> reports/$centre/report.$host.$date.txt
	grep 'least strength' logs/$centre/$host.tls-support.$date.txt | awk '{print $2" "$3" "$4}' >> reports/$centre/report.$host.$date.txt

	
	# 17. Web server is protected from POODLE attack
	# Check the nmap report
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '17. Web server is protected from POODLE attack: ' >> reports/$centre/report.$host.$date.txt
	if grep 'State: VULNERABLE' logs/$centre/$host.tls-poodle.$date.txt > /dev/null
	then
		echo 'No ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi

	# 18. Web server is protected from Logjam attack
	# Check the nmap report
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '18. Web server is protected from Logjam attack: ' >> reports/$centre/report.$host.$date.txt
	if grep 'State: VULNERABLE' logs/$centre/$host.tls-logjam.$date.txt > /dev/null
	then
		echo 'No ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 19. Web server is protected from Heartbleed attack
	# Check the nmap report
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '19. Web server is protected from Heartbleed attack: ' >> reports/$centre/report.$host.$date.txt
	if grep 'State: VULNERABLE' logs/$centre/$host.tls-heartbleed.$date.txt > /dev/null
	then
		echo 'No ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 20. Web server is protected from CRIME attack
	# We sent a compression request from client. If server agrees, probably it is vulnearable to CRIME.
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '20. Web server is protected from CRIME attack: ' >> reports/$centre/report.$host.$date.txt
	if grep -i 'Content-Encoding' logs/$centre/$host.tls-crime.$date.txt > /dev/null
	then
		echo -n 'Maybe, ' >> reports/$centre/report.$host.$date.txt
		grep -i 'Content-Encoding' logs/$centre/$host.tls-crime.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 21. Web server is protected from CCS Injection Vulnerability
	# Check the nmap report
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '21. Web server is protected from CCS Injection Vulnerability: ' >> reports/$centre/report.$host.$date.txt
	if grep 'State: VULNERABLE' logs/$centre/$host.tls-ccs-injection.$date.txt > /dev/null
	then
		echo 'No ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 22. Web server is protected from Anonymous Cipher Vulnerability
	# We tried to connect to the server using Anonymous cipher. If it succeeded, then the server is vulnearable.
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '22. Web server is protected from Anonymous Cipher Vulnerability: ' >> reports/$centre/report.$host.$date.txt
	if grep 'no peer certificate available' logs/$centre/$host-tls-anon.$date.txt > /dev/null
	then
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	else
		echo 'No' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 23. Web server is protected from Openssl FREAK Vulnerability
	# If nmap reports precense of EXPORT ciphers, then FREAK exists
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '23. Web server is protected from Openssl FREAK Vulnerability: ' >> reports/$centre/report.$host.$date.txt
	if grep 'EXPORT' logs/$centre/$host.tls-support.$date.txt > /dev/null
	then
		echo 'No' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	

	# 24. Web server is protected from SSL2 DROWN Vulnerability
	# Check the nmap report
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '24. Web server is protected from SSL2 DROWN Vulnerability: ' >> reports/$centre/report.$host.$date.txt
	if grep 'State: VULNERABLE' logs/$centre/$host.tls-drown.$date.txt > /dev/null
	then
		echo 'No ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 25. Webserver supports Forwarding Secrecy over SSL
	# If nmap reports ephemeral keys, the forward secrecy is supported
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '25. Webserver supports Forwarding Secrecy over SSL: ' >> reports/$centre/report.$host.$date.txt
	if grep 'DHE' logs/$centre/$host.tls-support.$date.txt > /dev/null
	then
		echo 'Yes ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'No' >> reports/$centre/report.$host.$date.txt
	fi
	
	# 26. DNS CAA is setup on DNS
	# Just perform the DNS lookup
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '26. DNS CAA is setup on DNS: ' >> reports/$centre/report.$host.$date.txt
	if grep -i 'issue' logs/$centre/$host.dns-caa-host.$date.txt > /dev/null
	then
		echo 'Yes, CAA record present in host ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'No, CAA record not present in host' >> reports/$centre/report.$host.$date.txt
	fi


	if grep -i 'issue' logs/$centre/$host.dns-caa-domain.$date.txt > /dev/null
	then
		echo 'Yes, CAA record present in domain ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'No, CAA record not present in domain' >> reports/$centre/report.$host.$date.txt
	fi



	# 27. Web server blocked the HTTP/1.0 response
	# Why are we even testing this?
	echo '' >> reports/$centre/report.$host.$date.txt
	echo '27. Web server blocked the HTTP/1.0 response: ' >> reports/$centre/report.$host.$date.txt
	if grep 'HTTP/1.0' logs/$centre/$host.curl.$date.txt > /dev/null
	then
		echo 'No ' >> reports/$centre/report.$host.$date.txt
	else
		echo 'Yes' >> reports/$centre/report.$host.$date.txt
	fi
fi

echo 'Done'

echo 'Report Saved'

echo ''
echo '-----------------------------------------------------------------'
cat reports/$centre/report.$host.$date.txt
echo '-----------------------------------------------------------------'
