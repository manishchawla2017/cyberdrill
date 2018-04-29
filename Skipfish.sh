#!/bin/bash

tmpDir=/tmp
URL= $1
PORT= $2

if [ $# == 0 ] ; then
	echo "Usage $0 <url> <port> "
	echo "example : $0 https://www.isro.gov.in  443 " 
else
   if [ $# ==  2 ]; then 
	rm -rf /tmp/result
	echo "Results are available in path"
	echo "/tmp/result"
	skipfish  -o /tmp/result -b f $1:$2
	
   else
	echo "Usage $0 <url> <port>"
        echo "example : $0 https://www.isro.gov.in  443 "

  fi

fi
