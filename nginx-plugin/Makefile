# 定义目标文件
TARGET_DIR=/usr/local/nginx
NGINX_VERSION=nginx-1.18.0
MODULE_DIR=../flow_detect_plugin

# 默认目标
all: install

# 配置目标：执行configure脚本
configure:
	chmod +x $(NGINX_VERSION)/configure
	rm -rf $(TARGET_DIR)
	cd $(NGINX_VERSION) && ./configure --add-dynamic-module=$(MODULE_DIR)  --with-compat --prefix=$(TARGET_DIR) --with-debug

# 编译并安装
install: configure
	cd $(NGINX_VERSION) && make && make install
	cd -

# 清理
clean:
	rm -rf $(TARGET_DIR)
	cd $(NGINX_VERSION) && make clean

.PHONY: all configure install clean
