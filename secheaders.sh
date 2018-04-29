#!/bin/bash
runDir=/root/drill/src
logDir=/root/drill/log/secheaders
srcDir=/root/drill/secheaders
url=`cat $runDir/websites.port.url`

cd $srcDir

for urls in $url
do
  echo $urls
  echo "Initiatiting Header Scan"
  python secheaders.py $urls > $logDir/$urls.headers &
done
