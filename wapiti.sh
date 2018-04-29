#!/bin/bash
runDir=/root/drill/src
logDir=/root/drill/log/wapiti
srcDir=/root/drill/secheader
url=`cat $runDir/websites.wapiti`

cd $srcDir

for urls in $url
do
  echo $urls
  echo "Initiatiting WAPITI Scan"
  wapiti -u $urls  &
done
