# 背景：

[GitHub - owasp-modsecurity/ModSecurity-nginx: ModSecurity v3 Nginx Connector](https://github.com/owasp-modsecurity/ModSecurity-nginx)  该项目新增一个nginx插件，在插件中调用ModSecurity库对http流量进行安全检测。

![未命名绘图 drawio (10)](https://github.com/user-attachments/assets/e1611bc2-77bd-4091-975b-2203dc3b1cbe)

该流程有2个问题：

1、将安全检测逻辑和nginx耦合到一起，安全检测的业务是不断更新的，如果有问题可能会导致nginx崩溃，从而引起客户业务中断。

2、nginx是IO密集型的，主要作为流量转发，没有特别复杂的业务，安全检测业务往往是cpu密集型，不适合和nginx耦合到一起，会阻塞nginx的流量解析转发流程。

针对上述问题：

该项目将ModeSecurity和nginx拆开作为单独的一个进程。

这样做的优点：

1、安全检测进程崩溃，不影响nginx的流量转发

2、安全检测进程检测某个http请求的流量时，nginx不需要同步等待，此时可以处理其他http请求的流量。

3、当安全监测性能低时，可以启动多个进程，nginx根据源ip和源端口，将流量转发给这些进程做检测。

4、安全检测进程可以不断更新业务，不影响nginx

![ModSecurity based onginx drawio (1)](https://github.com/user-attachments/assets/a97969b2-8c64-44f5-9c52-f669bdc22b75)

# 安装

1、安装nginx

cd nginx-plugin

./install.sh

可执行程序：/usr/local/nginx/sbin/nginx

配置文件：/usr/local/nginx/sbin/conf/nginx.conf

2、安装firewall_detect

cd ModSecurityDetect

./install.sh

可执行程序：ModSecurity_Based_Nginx/ModSecurityDetect/firewall_detect

配置文件：/etc/modSecurityDetect/config/detect.ini

# 测试

测试环境：8c16g

上游服务器是nginx，开1个worker进程，响应报文大小为1k

modSecurity使用默认配置

1、nginx和modSecurity解耦

1个nginx worker + 2个modSecurity

jmeter 开启10个线程，每个线程建立一个长连接，每个连接发包速度为200个请求/s

qps为1300条/s  平均时延 2ms

2、nginx和modSecurity耦合到一起

2个nginx worker

jmeter 开启10个线程，每个线程建立一个长连接，每个连接发包速度为200个请求/s

qps为1200条/s  平均时延 3ms

综上：nginx和ModSecurity解耦后的性能相比解耦前差不多，没有下降。

# Usage

flow_detect_switch
-----------
**syntax:** *flow_detect_switch on | off*

**context:** *http, server, location*

**default:** *off*

ModSecurity检测开关

flow_detect_buffer_size
-----------
**syntax:** *flow_detect_buffer_size size*

**context:** *http, server, location*

**default:** *4k|8k*

该buffer用来接收firewall_detect进程检测结果

默认是linux 页大小

flow_detect_connect_timeout
-----------
**syntax:** *flow_detect_connect_timeout time*

**context:** *http, server, location*

**default:** *1s*

和firewall_detect进程建立tcp连接需要的最长时间

flow_detect_send_timeout
-----------
**syntax:** *flow_detect_send_timeout time*

**context:** *http, server, location*

**default:** *1s*

发送数据包给firewall_detect所需的最长时间

flow_detect_read_timeout
-----------
**syntax:** *flow_detect_read_timeout time*

**context:** *http, server, location*

**default:** *1s*

读取firewall_detect进程检测结果所需做长时间

flow_detect_req_body_size
-----------
**syntax:** *flow_detect_req_body_size size*

**context:** *http, server, location*

**default:** *8k|16k*

待检测的请求body上限，超过截断，默认2倍的页大小

flow_detect_rsp_body_size
-----------
**syntax:** *flow_detect_rsp_body_size size*

**context:** *http, server, location*

**default:** *8k|16k*

待检测的响应body上限，超过截断，默认2倍的页大小

flow_detect_rsp_buffer_size
-----------
**syntax:** *flow_detect_rsp_buffer_size size*

**context:** *http, server, location*

**default:** *8k|16k*

该buffer用来缓存响应body，响应body超过buffer大小，则存文件

flow_detect_rsp_temp_path
-----------
**syntax:** *flow_detect_rsp_temp_path path [level1 [level2 [level3]]]*

**context:** *http, server, location*

**default:** **

当响应body太大时，flow_detect_rsp_buffer_size对应的缓冲区存不下，则存文件

例子：flow_detect_temp_path /usr/local/nginx/detect_rsp_body_tmp 1 2






