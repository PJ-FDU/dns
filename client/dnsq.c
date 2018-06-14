#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../model/dns_data_pack.h"

#define LOCAL_SERVER_IP "127.0.1.1"
#define LOCAL_SERVER_PORT 53

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("请输入查询类型和查询对象！\n");
    }
    else
    {
        char query_type = 0;
        char query_dn[BUF_SIZE] = {0};
        if (strcmp(argv[1], "-MX") == 0)
            query_type = MX;
        else if (strcmp(argv[1], "-CNAME") == 0)
            query_type = CNAME;
        else
            query_type = A;
        strcpy(query_dn, argv[2]);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
        serv_addr.sin_port = htons(LOCAL_SERVER_PORT);
        connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)); //连接服务器

        PackageHeader *qPackageHeader;
        qPackageHeader = (PackageHeader *)malloc(sizeof(PackageHeader));
        PackageQueries *qPackageQueries;
        qPackageQueries = (PackageQueries *)malloc(sizeof(PackageQueries));
        DnsPackage *qDnsPackage;
        qDnsPackage = (DnsPackage *)malloc(sizeof(DnsPackage));

        (*qPackageHeader).transaction_id = (unsigned short)time(NULL);
        (*qPackageHeader).flags = 0x0100;
        (*qPackageHeader).questions = 1;
        (*qPackageHeader).answer_rrs = 0;
        (*qPackageHeader).authority_rrs = 0;
        (*qPackageHeader).additional_rrs = 0;
        strcpy((*qPackageQueries).name, query_dn);
        (*qPackageQueries).type = query_type;
        (*qPackageQueries).class_ = IN;
        (*qDnsPackage).header = qPackageHeader;
        (*qDnsPackage).queries = qPackageQueries;

        char query_pack[BUF_SIZE] = {0};
        int query_pack_size = dnsPackage2code(query_pack, qDnsPackage);

        write(sock, query_pack, query_pack_size); //发送查询内容

        char res_code[BUF_SIZE] = {0};

        PackageHeader *rPackageHeader;
        rPackageHeader = (PackageHeader *)malloc(sizeof(PackageHeader));
        PackageQueries *rPackageQueries;
        rPackageQueries = (PackageQueries *)malloc(sizeof(PackageQueries));
        PackageAnswers *rPackageAnswers;
        rPackageAnswers = (PackageAnswers *)malloc(sizeof(PackageAnswers));
        PackageAdditionalRecords *rPackageAdditionalRecords;
        rPackageAdditionalRecords = (PackageAdditionalRecords *)malloc(sizeof(PackageAdditionalRecords));
        DnsPackage *rDnsPackage;
        rDnsPackage = (DnsPackage *)malloc(sizeof(DnsPackage));
        (*rDnsPackage).header = rPackageHeader;
        (*rDnsPackage).queries = rPackageQueries;
        (*rDnsPackage).answers = rPackageAnswers;
        (*rDnsPackage).additional_records = rPackageAdditionalRecords;

        size_t rd_len = read(sock, res_code, sizeof(res_code) - 1); //接收查询结果

        code2dnsPackage(rDnsPackage, res_code, rd_len);

        char rc_a_buf[BUF_SIZE] = {0};
        char rt_a_buf[BUF_SIZE] = {0};
        int2charQC(rc_a_buf, (*(*rDnsPackage).answers).class_);
        int2charQT(rt_a_buf, (*(*rDnsPackage).answers).type);
        printf(">>> %s\t%d\t%s\t%s\t%s\n", (*(*rDnsPackage).answers).name,
               (*(*rDnsPackage).answers).time_to_live,
               rc_a_buf,
               rt_a_buf,
               (*(*rDnsPackage).answers).data);
        if ((*(*rDnsPackage).header).additional_rrs != 0)
        {
            char rc_ad_buf[BUF_SIZE] = {0};
            char rt_ad_buf[BUF_SIZE] = {0};
            int2charQC(rc_ad_buf, (*(*rDnsPackage).additional_records).class_);
            int2charQT(rt_ad_buf, (*(*rDnsPackage).additional_records).type);
            printf(">>> %s\t%d\t%s\t%s\t%s\n", (*(*rDnsPackage).additional_records).name,
                   (*(*rDnsPackage).additional_records).time_to_live,
                   rc_ad_buf,
                   rt_ad_buf,
                   (*(*rDnsPackage).additional_records).data);
        }
        free((*qDnsPackage).header);
        free((*qDnsPackage).queries);
        free(qDnsPackage);
        free((*rDnsPackage).header);
        free((*rDnsPackage).queries);
        free((*rDnsPackage).answers);
        free((*rDnsPackage).additional_records);
        free(rDnsPackage);
        close(sock);
    }
    return 0;
}
