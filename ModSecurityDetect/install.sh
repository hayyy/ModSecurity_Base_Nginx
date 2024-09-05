#!/bin/bash

cd thirdpart
CUR_DIR=`pwd`

# 安装modsecurity
wget http://www.modsecurity.cn/download/modsecurity/modsecurity-v3.0.4.tar.gz
tar xzvf modsecurity-v3.0.4.tar.gz
cd modsecurity-v3.0.4
sudo apt-get update
sudo apt-get install -y gcc make autoconf automake libtool libpcre3 libpcre3-dev \
libxml2 libxml2-dev libyajl-dev libssl-dev libcurl4-openssl-dev apache2-dev
chmod +x build.sh
./build.sh
./configure
make
make install
cd ${CUR_DIR}

# 安装http_parser
cd http-parser
make
make install
cd ${CUR_DIR}

# cmake
wget https://cmake.org/files/v3.29/cmake-3.29.7.tar.gz
tar xzvf cmake-3.29.7.tar.gz
apt-get install doxygen
cd cmake-3.29.7
./bootstrap
make
make install
rm -f /usr/bin/cmake
ln -s /usr/local/bin/cmake /usr/bin/cmake
cd ${CUR_DIR}

# 安装iniparser
cd iniparser
mkdir build
cd build
cmake ..
make all
make install
cd ${CUR_DIR}

# 安装jemalloc
wget https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2
tar -xvf jemalloc-5.3.0.tar.bz2
cd jemalloc-5.3.0
./configure --with-jemalloc-prefix=je_
make
make install
cd ${CUR_DIR}

#安装tinylog
cd tinylog
make
make install
cd ${CUR_DIR}

# 编译firewall_detect
cd ..
export LD_LIBRARY_PATH=/usr/local/modsecurity/lib:/usr/local/lib:$LD_LIBRARY_PATH
make
mkdir -p /etc/modSecurityDetect/
cp -rf config /etc/modSecurityDetect/
mkdir -p /var/log/modSecurityDetect/
cd ${CUR_DIR}

#安装waf规则
wget http://www.modsecurity.cn/download/corerule/owasp-modsecurity-crs-3.3-dev.zip
unzip owasp-modsecurity-crs-3.3-dev.zip
cd owasp-modsecurity-crs-3.3-dev
cp crs-setup.conf.example /etc/modSecurityDetect/config/crs-setup.conf

cp -rf rules /etc/modSecurityDetect/
cd /etc/modSecurityDetect/rules
cp REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
cp RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
cd -

cp ${CUR_DIR}/modsecurity-v3.0.4/modsecurity.conf-recommended /etc/modSecurityDetect/config/modsecurity.conf
cp ${CUR_DIR}/modsecurity-v3.0.4/unicode.mapping /etc/modSecurityDetect/config/

echo "Include /etc/modSecurityDetect/config/crs-setup.conf" >> /etc/modSecurityDetect/config/modsecurity.conf
echo "Include /etc/modSecurityDetect/rules/*.conf" >> /etc/modSecurityDetect/config/modsecurity.conf
