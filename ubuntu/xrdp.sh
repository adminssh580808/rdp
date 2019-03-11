echo "====================================="
echo "   Selamat Datang di Setting XRDP"
echo "====================================="
sudo apt-get update -y 
sudo apt-get install -y xfce4 xfce4-goodies
sudo apt-get install -y firefox
sudo apt-get install -y xrdp
echo xfce4-session >~/.xsession
sudo service xrdp start
apt-get install -y xfonts-100dpi xfonts-100dpi-transcoded xfonts-75dpi xfonts-75dpi-transcoded xfonts-base
apt-get install -y tightvncserver
tightvncserver :1
reboot
