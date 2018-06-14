#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../model/dns_data_pack.h"

static char serv_ip[BUF_SIZE] = {0};
static int serv_port = 0;

static RR rr[BUF_SIZE];
static int rr_num = 0;

void initConfig(char config[])
{
    FILE *fp = NULL;
    fp = fopen(config, "r");
    fscanf(fp, "%s", &serv_ip);
    fscanf(fp, "%d", &serv_port);
    while (!feof(fp))
    {
        fscanf(fp, "%s", &rr[rr_num].dn);
        fscanf(fp, "%d", &rr[rr_num].ttl);
        char qc_tmp[BUF_SIZE] = {0};
        char qt_tmp[BUF_SIZE] = {0};
        fscanf(fp, "%s", &qc_tmp);
        fscanf(fp, "%s", &qt_tmp);
        rr[rr_num].qc = char2intQC(qc_tmp);
        rr[rr_num].qt = char2intQT(qt_tmp);
        fscanf(fp, "%s", &rr[rr_num].data);

        rr_num++;
    }
    fclose(fp);
}

void startServer()
{
    int serv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(serv_ip);
    serv_addr.sin_port = htons(serv_port);
    bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("远程DNS服务器启动成功! 远程服务器运行IP: %s， 端口: %d\n", serv_ip, serv_port);

    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    char clnt_qp[BUF_SIZE] = {0};

    while (1)
    {
        memset(clnt_qp, 0, sizeof(clnt_qp));
        size_t recv_len = recvfrom(serv_sock, clnt_qp, sizeof(clnt_qp), 0, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

        //构建查询数据包
        PackageHeader *recv_ph;
        recv_ph = (PackageHeader *)malloc(sizeof(PackageHeader));
        PackageQueries *recv_pq;
        recv_pq = (PackageQueries *)malloc(sizeof(PackageQueries));
        DnsPackage *recv_dp;
        recv_dp = (DnsPackage *)malloc(sizeof(DnsPackage));
        (*recv_dp).header = recv_ph;
        (*recv_dp).queries = recv_pq;

        memset((*(*recv_dp).queries).name, 0, BUF_SIZE);
        code2dnsPackage(recv_dp, clnt_qp, recv_len);

        char recv_class[BUF_SIZE] = {0};
        char recv_type[BUF_SIZE] = {0};
        int2charQC(recv_class, (*(*recv_dp).queries).class_);
        int2charQT(recv_type, (*(*recv_dp).queries).type);
        printf("<<< %s\t%s\t%s\n", (*(*recv_dp).queries).name, recv_class, recv_type);

        // 构建返回数据包
        PackageHeader *s_ph;
        s_ph = (PackageHeader *)malloc(sizeof(PackageHeader));
        PackageQueries *s_pq;
        s_pq = (PackageQueries *)malloc(sizeof(PackageQueries));
        PackageAnswers *s_pa;
        s_pa = (PackageAnswers *)malloc(sizeof(PackageAnswers));
        PackageAdditionalRecords *s_par;
        s_par = (PackageAdditionalRecords *)malloc(sizeof(PackageAdditionalRecords));
        DnsPackage *s_dp;
        s_dp = (DnsPackage *)malloc(sizeof(DnsPackage));
        (*s_dp).header = s_ph;
        (*s_dp).queries = s_pq;
        (*s_dp).answers = s_pa;
        (*s_dp).additional_records = s_par;

        int idx = queryData((*(*recv_dp).queries).name, (*(*recv_dp).queries).class_, (*(*recv_dp).queries).type);

        if (idx > -1)
        {
            char qc_a_buf[BUF_SIZE] = {0};
            char qt_a_buf[BUF_SIZE] = {0};
            int2charQC(qc_a_buf, rr[idx].qc);
            int2charQT(qt_a_buf, rr[idx].qt);
            printf(">>> %s\t%d\t%s\t%s\t%s\n", rr[idx].dn, rr[idx].ttl, qc_a_buf, qt_a_buf, rr[idx].data);
        }

        int idx_ = -1;
        if ((*(*recv_dp).queries).type == MX)
        {
            idx_ = queryData(rr[idx].data, IN, A);

            char qc_ad_buf[BUF_SIZE] = {0};
            char qt_ad_buf[BUF_SIZE] = {0};
            int2charQC(qc_ad_buf, rr[idx_].qc);
            int2charQT(qt_ad_buf, rr[idx_].qt);
            printf(">>> %s\t%d\t%s\t%s\t%s\n", rr[idx_].dn, rr[idx_].ttl, qc_ad_buf, qt_ad_buf, rr[idx_].data);
        }

        (*(*s_dp).header).transaction_id = (*(*recv_dp).header).transaction_id;
        (*(*s_dp).header).flags = 0x8180;
        (*(*s_dp).header).questions = (*(*recv_dp).header).questions;
        (*(*s_dp).header).answer_rrs = idx > -1 ? 1 : 0;
        (*(*s_dp).header).authority_rrs = 0;
        (*(*s_dp).header).additional_rrs = idx_ > -1 ? 1 : 0;

        if ((*(*s_dp).header).questions != 0)
        {
            memset((*(*s_dp).queries).name, 0, BUF_SIZE);
            strcpy((*(*s_dp).queries).name, (*(*recv_dp).queries).name);
            (*(*s_dp).queries).type = (*(*recv_dp).queries).type;
            (*(*s_dp).queries).class_ = (*(*recv_dp).queries).class_;
        }

        if ((*(*s_dp).header).answer_rrs != 0)
        {
            memset((*(*s_dp).answers).name, 0, BUF_SIZE);
            strcpy((*(*s_dp).answers).name, (*(*recv_dp).queries).name);
            (*(*s_dp).answers).type = (*(*recv_dp).queries).type;
            (*(*s_dp).answers).class_ = (*(*recv_dp).queries).class_;
            (*(*s_dp).answers).time_to_live = rr[idx].ttl;
            memset((*(*s_dp).answers).data, 0, BUF_SIZE);
            strcpy((*(*s_dp).answers).data, rr[idx].data);
            (*(*s_dp).answers).data_length = strlen((*(*s_dp).answers).data);
        }

        if ((*(*s_dp).header).additional_rrs != 0)
        {
            memset((*(*s_dp).additional_records).name, 0, BUF_SIZE);
            strcpy((*(*s_dp).additional_records).name, rr[idx_].dn);
            (*(*s_dp).additional_records).type = rr[idx_].qt;
            (*(*s_dp).additional_records).class_ = rr[idx_].qc;
            (*(*s_dp).additional_records).time_to_live = rr[idx_].ttl;
            memset((*(*s_dp).additional_records).data, 0, BUF_SIZE);
            strcpy((*(*s_dp).additional_records).data, rr[idx_].data);
            (*(*s_dp).additional_records).data_length = strlen((*(*s_dp).additional_records).data);
        }

        // 封装返回数据包
        char s_code[BUF_SIZE] = {0};

        int s_code_len = dnsPackage2code(s_code, s_dp);

        // 发送数据
        sendto(serv_sock, s_code, s_code_len, 0, (struct sockaddr *)&clnt_addr, clnt_addr_size);
        memset(clnt_qp, 0, strlen(clnt_qp));
        free(recv_dp);
        free(recv_ph);
        free(recv_pq);
        free(s_dp);
        free(s_ph);
        free(s_pq);
        free(s_pa);
        free(s_par);
    }

    close(serv_sock);
}

int queryData(char data[], int q_class, int q_type)
{
    for (int i = 0; i < rr_num; i++)
        if ((strcmp(rr[i].dn, data) == 0) && (q_class == rr[i].qc) && (q_type = rr[i].qt))
            return i;
    return -1;
}

int main(int argc, char const *argv[])
{
    printf("正在开启远程DNS服务器...\n");
    if (argc == 1)
    {
        printf("请输入一份DNS服务器配置文件!\n");
    }
    else
    {
        initConfig((char *)argv[1]);
        startServer();
    }
    return 0;
}
