#################################################################################
ʹ��˵��:
1. ����client, local_ns, remote_ns
	1.1. gcc -w --std=c99 ./dnsq.c ../model/dns_data_pack.c -o dnsq
	1.2. gcc -w --std=c99 ./local_ns.c ../model/dns_data_pack.c -o local_ns
	1.3. gcc -w --std=c99 ./remote_ns.c ../model/dns_data_pack.c -o remote_ns
2. ���з�����(ȫ����rootȨ��������)
	1.1. sudo ./remote_ns ../db/root.txt
	1.2. sudo ./remote_ns ../db/�й�.txt
	1.3. sudo ./remote_ns ../db/����.�й�.txt
	1.4. sudo ./remote_ns ../db/����.����.�й�.txt
	1.5. sudo ./local_ns
3. ��ѯ
	1.1. ./dnsq A ��ҳ.����.����.�й�
	1.2. ./dnsq -MX ����.����.�й�
	1.3. ./dnsq -CNAME ��ҳ.����.����.�й�
#################################################################################