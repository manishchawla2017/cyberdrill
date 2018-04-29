#!/bin/bash
#@Author Manish

if [ $# == 0 ] ; then
	echo "Usage $0 <url> <port> "
else
	if  [ $# == 2 ] ; then 
		echo "If there is no output for any test, it means nothing found, it will only show port number scanned"
		echo "Identifying http headers"
 		nmap -p$2  --script http-methods --script-args http.useragent="Mozilla 54"  $1
		echo " "
		echo "Testing Methods"
		nmap -p$2  --script http-methods --script-args http.useragent="Mozilla 54" --script-args http-methods.test-all   $1
		echo " Testing Trace Method"
		nmap -p$2  --script http-trace --script-args http.useragent="Mozilla 54"   $1
		echo "Testing Stored XSS"
		nmap -p$2  --script http-stored-xss --script-args http.useragent="Mozilla 54"  $1
		echo "Testing  http-slowloris-check "
		 nmap -p$2  --script http-slowloris-check --script-args http.useragent="Mozilla 54"  $1
	        echo " Testing  http-cross-domain-policy"
		nmap -p$2  --script http-cross-domain-policy --script-args http.useragent="Mozilla 54"  $1
		echo " Testing  http-csrf "
		nmap -p$2  --script http-csrf --script-args http.useragent="Mozilla 54"  $1
	 	echo " Testing http DOMBased XSS"
		nmap -p$2  --script http-dombased-xss --script-args http.useragent="Mozilla 54"  $1	
		echo "Testing  http-aspnet-debug"
		nmap -p$2  --script http-aspnet-debug  --script-args http.useragent="Mozilla 54"  $1
		echo "Testing  http-fileupload-exploiter"
		nmap -p$2  --script http-fileupload-exploiter  --script-args http.useragent="Mozilla 54"  $1
		echo "Testing Security Headers"
		nmap -p$2  --script http-security-headers --script-args http.useragent="Mozilla 54"  $1
		echo "Testing IIS Vulnerability"
		nmap -p$2  --script http-iis-webdav-vuln  --script-args http.useragent="Mozilla 54"  $1
		echo "Testing Internal IP Disclosure"
		nmap -p$2  --script http-internal-ip-disclosure  --script-args http.useragent="Mozilla 54"  $1		
	        echo "Testing Verb Tampering"
		nmap -p$2  --script http-method-tamper  --script-args http.useragent="Mozilla 54"  $1
		echo "Testing php self"
		nmap -p$2  --script http-phpself-xss  --script-args http.useragent="Mozilla 54"  $1
		echo "Testing ShellShocK"
		nmap -p$2  --script http-shellshock --script-args http.useragent="Mozilla 54"  $1
		
		else
		echo "Usage $0 <url> <port> "
	fi 
fi

#nmap -sV --script=http-headers <target>
