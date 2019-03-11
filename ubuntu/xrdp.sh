echo "===================================="
echo "Selamat Datang di Fawzya.Net"
echo "===================================="
sudo apt-get update -y 
sudo apt-get install -y xfce4 xfce4-goodies
sudo apt-get install -y firefox
sudo apt-get install -y xrdp
echo xfce4-session >~/.xsession
sudo service xrdp start