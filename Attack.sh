#!/bin/bash 
runDir=/root/drill/bin
logDir=/root/drill/log
srcDir=/root/drill/src
url=`cat $srcDir/websites.url`

nmap_scripts=/usr/share/nmap/scripts
cd $srcDir

for urls in $url 
do
 echo $urls
  echo "Initiatiting NMAP Scan"
 	nmap -p- -Pn -sV $urls > $logDir/$urls.nmap & 
#echo "Initiating  sslyze "
# sslyze --regular $url > $logDir/$url.sslyze & 
# echo "SSL handshack Check"
# echo QUIT | openssl s_client -connect $url:443 -servername $url:443 -tls1 -tlsextdebug -status > $logDir/$url.openssl & 
#echo "Initiating Nikto Scan"
#nikto -h $url > $logDir/$url.nikto & 
#echo "Carrying  out busting of directory"
#  dirb http://$url > $logDir/$url.dirb  &
#  dirb https://$url >> $logDir/$url.dirb & 
#echo "Initiating  Grabber"
#grabber -s -x -b -z -i  -j -e -u  $url > $logDir/$url.grabber & 
#echo "Initiating Uniscan "
#uniscan -u $url  > $logDir/$url.uniscan &
#echo "Initiating a2sv Scan"
# a2sv -t  $url -o $logDir/$url.a2sv  & 

done 

