echo "
===========================================
       Selamat Datang Di Script XRDP
==========================================="
yum groupinstall "GNOME Desktop" -y
rpm -Uvh https://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-8.noarch.rpm
rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-1.el7.nux.noarch.rpm
yum install xrdp tigervnc-server -y
chcon -t bin_t /usr/sbin/xrdp-sesman
chcon -t bin_t /usr/sbin/xrdp
firewall-cmd --permanent --zone=public --add-port=3389/tcp
firewall-cmd --reload
systemctl start xrdp.service
systemctl enable xrdp.service
systemctl status xrdp.service
systemctl set-default graphical.target
