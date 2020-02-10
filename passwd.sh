#!/bin/sh

WEB_LOGIN="admin:gx6605s"

WEB_PASS=`echo -n "$WEB_LOGIN:admin" | md5sum | cut -f1 -d " "`

echo "$WEB_LOGIN:$WEB_PASS" > ./htpasswd
