#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

wget -N --no-check-certificate https://raw.githubusercontent.com/aiastia/k-z/master/ss.sh && bash ss.sh && rm -rf *.sh
