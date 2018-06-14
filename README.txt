#################################################################################
使用说明:
1. 编译client, local_ns, remote_ns
	1.1. gcc -w --std=c99 ./dnsq.c ../model/dns_data_pack.c -o dnsq
	1.2. gcc -w --std=c99 ./local_ns.c ../model/dns_data_pack.c -o local_ns
	1.3. gcc -w --std=c99 ./remote_ns.c ../model/dns_data_pack.c -o remote_ns
2. 运行服务器(全部在root权限下运行)
	1.1. sudo ./remote_ns ../db/root.txt
	1.2. sudo ./remote_ns ../db/中国.txt
	1.3. sudo ./remote_ns ../db/教育.中国.txt
	1.4. sudo ./remote_ns ../db/北邮.教育.中国.txt
	1.5. sudo ./local_ns
3. 查询
	1.1. ./dnsq A 主页.北邮.教育.中国
	1.2. ./dnsq -MX 北邮.教育.中国
	1.3. ./dnsq -CNAME 首页.北邮.教育.中国
#################################################################################