#!/bin/bash

# run as sudo
if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
    exit
fi

apt -y update
apt -y install git make curl python3-pip

# commonspeak install
git clone https://github.com/pentester-io/commonspeak.git
apt -y install jq
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
sudo apt-get -y install apt-transport-https ca-certificates gnupg
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update 
sudo apt-get -y install google-cloud-sdk
gcloud init

# amass install
apt -y install snapd
systemctl start snapd.service
snap install amass

# massdns install
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
make install
cd ..

# altdns install
pip install

# bass install
git clone https://github.com/Abss0x7tbh/bass.git
cd bass
python3 -m pip install -r requirements.txt
cd ..

# subjack install
apt -y install golang
go get github.com/haccer/subjack

# httprobe install
go get -u github.com/tomnomnom/httprobe

# install wordlists, words.txt inside altdns directory
mkdir wordlists
cd wordlists
wget https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt
cd ..

pip3 install -r requirements.txt