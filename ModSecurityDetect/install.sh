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

make
