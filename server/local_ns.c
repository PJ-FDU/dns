#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../model/dns_data_pack.h"

#define LOCAL_SERVER_IP "127.0.1.1"
#define LOCAL_SERVER_PORT 53
#define ROOT_SERVER_IP "127.0.0.2"
#define CACHE_FILE "./local_ns_cache.txt"

static RR rr_cache[BUF_SIZE];
static int rr_cache_size = 0;

void loadCache(char cache_file[])
{
    FILE *fp_cache = NULL;
    fp_cache = fopen(cache_file, "a+");
    while (!feof(fp_cache))
    {
        char domain_name[BUF_SIZE]; // 域名
        int time_to_live = -1;
        char query_class_buf[BUF_SIZE] = {0}; // 查询类
        int query_class = -1;
        char query_type_buf[BUF_SIZE] = {0}; // 查询类型
        int query_type = -1;
        char domain_data[BUF_SIZE]; // 域名信息

        // 按行读取
        fscanf(fp_cache, "%s%d%s%s%s", &domain_name, &time_to_live, &query_class_buf, &query_type_buf, &domain_data);

        // 将IN, A, CNAME, MX等字符转换为预先定义的整数值
        query_class = char2intQC(query_class_buf);
        query_type = char2intQT(query_type_buf);

        strcpy(rr_cache[rr_cache_size].dn, domain_name);
        rr_cache[rr_cache_size].ttl = time_to_live;
        rr_cache[rr_cache_size].qc = query_class;
        rr_cache[rr_cache_size].qt = query_type;
        strcpy(rr_cache[rr_cache_size].data, domain_data);

        rr_cache_size++;
    }
    fclose(fp_cache);
}

void addCache(char cache_file[], char qname[BUF_SIZE], int qttl, int qclass, int qtype, char qdata[BUF_SIZE])
{
    strcpy(rr_cache[rr_cache_size].dn, qname);
    rr_cache[rr_cache_size].ttl = qttl;
    rr_cache[rr_cache_size].qc = qclass;
    rr_cache[rr_cache_size].qt = qtype;
    strcpy(rr_cache[rr_cache_size].data, qdata);

    FILE *fp_cache = NULL;
    char qclass_buf[BUF_SIZE] = {0};
    char qtype_buf[BUF_SIZE] = {0};
    int2charQC(qclass_buf, qclass);
    int2charQT(qtype_buf, qtype);
    fp_cache = fopen(cache_file, "a+");
    fprintf(fp_cache, "%s\t%d\t%s\t%s\t%s\n", qname, qttl, qclass_buf, qtype_buf, qdata);
    rr_cache_size++;
    fclose(fp_cache);
}

int cacheQuery(char qname[BUF_SIZE], int qclass, int qtype)
{
    for (int i = 0; i < rr_cache_size; i++)
        if ((strcmp(qname, rr_cache[i].dn) == 0) && (qclass == rr_cache[i].qc) && (qtype == rr_cache[i].qt))
            return i;
    return -1;
};

size_t udpQuery(char res_buf[], char query_pack[], size_t query_pack_size, char target_ip[])
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port = htons(53);
    socklen_t serv_addr_size = sizeof(serv_addr);

    sendto(sock, query_pack, query_pack_size, 0, (struct sockaddr *)&serv_addr, serv_addr_size);
    size_t recv_size = recvfrom(sock, res_buf, BUF_SIZE, 0, (struct sockaddr *)&serv_addr, &serv_addr_size);
    return recv_size;
}

int main()
{
    printf("正在开启本地DNS服务器...\n");
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    serv_addr.sin_port = htons(LOCAL_SERVER_PORT);
    bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(serv_sock, 20);
    printf("本地DNS服务器启动成功！本地服务器运行IP: %s， 端口: %d\n", LOCAL_SERVER_IP, LOCAL_SERVER_PORT);

    loadCache(CACHE_FILE);
    printf("本地DNS服务器缓存加载成功！\n");

    struct sockaddr clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    char clnt_qp[BUF_SIZE] = {0};
    char res_code[BUF_SIZE] = {0};
    char ip_buf[BUF_SIZE] = ROOT_SERVER_IP;
    char dn[4][BUF_SIZE] = {{0}};
    int dn_class = 0;

    while (1)
    {
        int clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
        size_t rd_len = read(clnt_sock, clnt_qp, sizeof(clnt_qp) - 1);

        // 初始化客户端查询数据包
        PackageHeader *r_ph;
        r_ph = (PackageHeader *)malloc(sizeof(PackageHeader));
        PackageQueries *r_pq;
        r_pq = (PackageQueries *)malloc(sizeof(PackageQueries));
        DnsPackage *r_dp;
        r_dp = (DnsPackage *)malloc(sizeof(DnsPackage));
        (*r_dp).header = r_ph;
        (*r_dp).queries = r_pq;
        memset((*(*r_dp).queries).name, 0, BUF_SIZE);

        // 构建返回客户端的数据包
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

        // 解析客户端查询数据包
        code2dnsPackage(r_dp, clnt_qp, rd_len);

        char rc_buf[BUF_SIZE] = {0};
        char rt_buf[BUF_SIZE] = {0};
        int2charQC(rc_buf, (*(*r_dp).queries).class_);
        int2charQT(rt_buf, (*(*r_dp).queries).type);
        printf("<<< %s\t%s\t%s\n", (*(*r_dp).queries).name, rc_buf, rt_buf);

        // 先搜索缓存
        int idx = -1;  // 代表A, CNAME查找记录
        int idx_ = -1; // 代表MX查找记录
        idx = cacheQuery((*(*r_dp).queries).name, (*(*r_dp).queries).class_, (*(*r_dp).queries).type);
        if (idx > -1 && (*(*r_dp).queries).type == MX)
            idx_ = cacheQuery(rr_cache[idx].data, IN, A);
        if (idx > -1)
        {
            printf("在缓存中找到结果, 直接返回客户端!\n");
            (*(*s_dp).header).transaction_id = (*(*r_dp).header).transaction_id;
            (*(*s_dp).header).flags = 0x8180;
            (*(*s_dp).header).questions = (*(*r_dp).header).questions;
            (*(*s_dp).header).answer_rrs = 1;
            (*(*s_dp).header).authority_rrs = 0;
            (*(*s_dp).header).additional_rrs = (idx_ > -1) ? 1 : 0;
            if ((*(*s_dp).header).questions != 0)
            {
                memset((*(*s_dp).queries).name, 0, BUF_SIZE);
                strcpy((*(*s_dp).queries).name, (*(*r_dp).queries).name);
                (*(*s_dp).queries).type = (*(*r_dp).queries).type;
                (*(*s_dp).queries).class_ = (*(*r_dp).queries).class_;
            }
            if ((*(*s_dp).header).answer_rrs != 0)
            {
                memset((*(*s_dp).answers).name, 0, BUF_SIZE);
                strcpy((*(*s_dp).answers).name, rr_cache[idx].dn);
                (*(*s_dp).answers).type = rr_cache[idx].qt;
                (*(*s_dp).answers).class_ = rr_cache[idx].qc;
                (*(*s_dp).answers).time_to_live = rr_cache[idx].ttl;
                (*(*s_dp).answers).data_length = strlen(rr_cache[idx].data);
                memset((*(*s_dp).answers).data, 0, BUF_SIZE);
                strcpy((*(*s_dp).answers).data, rr_cache[idx].data);
            }
            if ((*(*s_dp).header).additional_rrs != 0)
            {
                memset((*(*s_dp).additional_records).name, 0, BUF_SIZE);
                strcpy((*(*s_dp).additional_records).name, rr_cache[idx_].dn);
                (*(*s_dp).additional_records).type = rr_cache[idx_].qt;
                (*(*s_dp).additional_records).class_ = rr_cache[idx_].qc;
                (*(*s_dp).additional_records).time_to_live = rr_cache[idx_].ttl;
                (*(*s_dp).additional_records).data_length = strlen(rr_cache[idx_].data);
                memset((*(*s_dp).additional_records).data, 0, BUF_SIZE);
                strcpy((*(*s_dp).additional_records).data, rr_cache[idx_].data);
            }

            char sc_a_buf[BUF_SIZE] = {0};
            char st_a_buf[BUF_SIZE] = {0};
            int2charQC(sc_a_buf, (*(*s_dp).answers).class_);
            int2charQT(st_a_buf, (*(*s_dp).answers).type);
            printf(">>> %s\t%d\t%s\t%s\t%s\n", (*(*s_dp).answers).name, (*(*s_dp).answers).time_to_live,
                   sc_a_buf, st_a_buf, (*(*s_dp).answers).data);

            if ((*(*s_dp).header).additional_rrs != 0)
            {
                char sc_ad_buf[BUF_SIZE] = {0};
                char st_ad_buf[BUF_SIZE] = {0};
                int2charQC(sc_ad_buf, (*(*s_dp).additional_records).class_);
                int2charQT(st_ad_buf, (*(*s_dp).additional_records).type);
                printf(">>> %s\t%d\t%s\t%s\t%s\n", (*(*s_dp).additional_records).name, (*(*s_dp).additional_records).time_to_live,
                       sc_ad_buf, st_ad_buf, (*(*s_dp).additional_records).data);
            }
        }
        else //缓存查找记录为0
        {
            printf("在缓存中未找到结果, 向远程服务器发起查询!\n");
            // 初始化迭代查询数据包
            PackageHeader *q_ph;
            q_ph = (PackageHeader *)malloc(sizeof(PackageHeader));
            PackageQueries *q_pq;
            q_pq = (PackageQueries *)malloc(sizeof(PackageQueries));
            DnsPackage *q_dp;
            q_dp = (DnsPackage *)malloc(sizeof(DnsPackage));
            (*q_dp).header = q_ph;
            (*q_dp).queries = q_pq;
            memset((*(*q_dp).queries).name, 0, BUF_SIZE);

            // 初始化迭代查询返回数据包
            PackageHeader *recv_ph;
            recv_ph = (PackageHeader *)malloc(sizeof(PackageHeader));
            PackageQueries *recv_pq;
            recv_pq = (PackageQueries *)malloc(sizeof(PackageQueries));
            PackageAnswers *recv_pa;
            recv_pa = (PackageAnswers *)malloc(sizeof(PackageAnswers));
            PackageAdditionalRecords *recv_par;
            recv_par = (PackageAdditionalRecords *)malloc(sizeof(PackageAdditionalRecords));
            DnsPackage *recv_dp;
            recv_dp = (DnsPackage *)malloc(sizeof(DnsPackage));
            (*recv_dp).header = recv_ph;
            (*recv_dp).queries = recv_pq;
            (*recv_dp).answers = recv_pa;
            (*recv_dp).additional_records = recv_par;

            // 将查询域名按照层次拆分
            for (int idx = strlen((*(*r_dp).queries).name) - 1; idx >= 0; idx--)
                if ((idx > 0 && (*(*r_dp).queries).name[idx - 1] == '.') || idx == 0)
                {
                    for (int i = 0; i < strlen((*(*r_dp).queries).name) - idx; i++)
                        dn[dn_class][i] = (*(*r_dp).queries).name[i + idx];
                    dn_class++;
                }

            if ((*(*r_dp).queries).type == MX)
                strcpy(dn[dn_class++], (*(*r_dp).queries).name);

            // 开始迭代查询
            for (int i = 0; i < dn_class; i++)
            {
                // 设置迭代查询数据包内容
                (*(*q_dp).header).transaction_id = (unsigned short)time(NULL);
                (*(*q_dp).header).flags = 0x0100;
                (*(*q_dp).header).questions = 1;
                (*(*q_dp).header).answer_rrs = 0;
                (*(*q_dp).header).authority_rrs = 0;
                (*(*q_dp).header).additional_rrs = 0;
                memset((*(*q_dp).queries).name, 0, BUF_SIZE);
                strcpy((*(*q_dp).queries).name, dn[i]);
                (*(*q_dp).queries).type = (i == dn_class - 1) ? (*(*r_dp).queries).type : A;
                (*(*q_dp).queries).class_ = IN;

                // 将迭代查询数据包打包
                char code[BUF_SIZE] = {0};
                int code_len = dnsPackage2code(code, q_dp);

                // 保存结果的字符数组
                char recv_code[BUF_SIZE] = {0};

                // 发送数据包进行查询
                size_t recv_size = udpQuery(recv_code, code, code_len, ip_buf);

                // 将结果解析到结果数据包
                memset((*(*recv_dp).queries).name, 0, BUF_SIZE);
                memset((*(*recv_dp).answers).name, 0, BUF_SIZE);
                memset((*(*recv_dp).answers).data, 0, BUF_SIZE);
                memset((*(*recv_dp).additional_records).name, 0, BUF_SIZE);
                memset((*(*recv_dp).additional_records).data, 0, BUF_SIZE);
                code2dnsPackage(recv_dp, recv_code, recv_size);

                char q_class[BUF_SIZE] = {0};
                char q_type[BUF_SIZE] = {0};
                int2charQC(q_class, (*(*q_dp).queries).class_);
                int2charQT(q_type, (*(*q_dp).queries).type);
                printf("<<< %s\t%s\t%s\n", (*(*q_dp).queries).name, q_class, q_type);

                if ((*(*recv_dp).header).answer_rrs != 0)
                {
                    char recv_a_class[BUF_SIZE] = {0};
                    char recv_a_type[BUF_SIZE] = {0};
                    int2charQC(recv_a_class, (*(*recv_dp).answers).class_);
                    int2charQT(recv_a_type, (*(*recv_dp).answers).type);
                    printf(">>> %s\t%d\t%s\t%s\t%s\n", (*(*recv_dp).answers).name,
                           (*(*recv_dp).answers).time_to_live,
                           recv_a_class,
                           recv_a_type,
                           (*(*recv_dp).answers).data);
                }

                if ((*(*recv_dp).header).additional_rrs != 0)
                {
                    char recv_ad_class[BUF_SIZE] = {0};
                    char recv_ad_type[BUF_SIZE] = {0};
                    int2charQC(recv_ad_class, (*(*recv_dp).additional_records).class_);
                    int2charQT(recv_ad_type, (*(*recv_dp).additional_records).type);
                    printf(">>> %s\t%d\t%s\t%s\t%s\n", (*(*recv_dp).additional_records).name,
                           (*(*recv_dp).additional_records).time_to_live,
                           recv_ad_class,
                           recv_ad_type,
                           (*(*recv_dp).additional_records).data);
                }

                // 更新下一步的目标服务器IP
                strcpy(ip_buf, (*(*recv_dp).answers).data);
            }

            (*(*s_dp).header).transaction_id = (*(*r_dp).header).transaction_id;
            (*(*s_dp).header).flags = 0x8180;
            (*(*s_dp).header).questions = (*(*r_dp).header).questions;
            (*(*s_dp).header).answer_rrs = (*(*recv_dp).header).answer_rrs;
            (*(*s_dp).header).authority_rrs = 0;
            (*(*s_dp).header).additional_rrs = (*(*recv_dp).header).additional_rrs;

            if ((*(*s_dp).header).questions != 0)
            {
                memset((*(*s_dp).queries).name, 0, BUF_SIZE);
                strcpy((*(*s_dp).queries).name, (*(*r_dp).queries).name);
                (*(*s_dp).queries).type = (*(*r_dp).queries).type;
                (*(*s_dp).queries).class_ = (*(*r_dp).queries).class_;
            }

            if ((*(*s_dp).header).answer_rrs != 0)
            {
                memset((*(*s_dp).answers).name, 0, BUF_SIZE);
                strcpy((*(*s_dp).answers).name, (*(*recv_dp).answers).name);
                (*(*s_dp).answers).type = (*(*recv_dp).answers).type;
                (*(*s_dp).answers).class_ = (*(*recv_dp).answers).class_;
                (*(*s_dp).answers).time_to_live = (*(*recv_dp).answers).time_to_live;
                (*(*s_dp).answers).data_length = (*(*recv_dp).answers).data_length;
                memset((*(*s_dp).answers).data, 0, BUF_SIZE);
                strcpy((*(*s_dp).answers).data, (*(*recv_dp).answers).data);

                // 更新缓存
                addCache(CACHE_FILE, (*(*s_dp).answers).name, (*(*s_dp).answers).time_to_live,
                         (*(*s_dp).answers).class_, (*(*s_dp).answers).type, (*(*s_dp).answers).data);
            }

            if ((*(*s_dp).header).additional_rrs != 0)
            {
                memset((*(*s_dp).additional_records).name, 0, BUF_SIZE);
                strcpy((*(*s_dp).additional_records).name, (*(*recv_dp).additional_records).name);
                (*(*s_dp).additional_records).type = (*(*recv_dp).additional_records).type;
                (*(*s_dp).additional_records).class_ = (*(*recv_dp).additional_records).class_;
                (*(*s_dp).additional_records).time_to_live = (*(*recv_dp).additional_records).time_to_live;
                (*(*s_dp).additional_records).data_length = (*(*recv_dp).additional_records).data_length;
                memset((*(*s_dp).additional_records).data, 0, BUF_SIZE);
                strcpy((*(*s_dp).additional_records).data, (*(*recv_dp).additional_records).data);

                // 更新缓存
                addCache(CACHE_FILE, (*(*s_dp).additional_records).name, (*(*s_dp).additional_records).time_to_live,
                         (*(*s_dp).additional_records).class_, (*(*s_dp).additional_records).type, (*(*s_dp).additional_records).data);
            }

            free(recv_dp);
            free(recv_ph);
            free(recv_pq);
            free(recv_pa);
            free(recv_par);
            free(q_dp);
            free(q_ph);
            free(q_pq);
        }

        int res_code_len = dnsPackage2code(res_code, s_dp);
        write(clnt_sock, res_code, res_code_len);
        close(clnt_sock);
        memset(clnt_qp, 0, BUF_SIZE);
        memset(res_code, 0, BUF_SIZE);
        memset(ip_buf, 0, BUF_SIZE);
        strcpy(ip_buf, ROOT_SERVER_IP);
        for (int i = 0; i < 4; i++)
            memset(dn[i], 0, BUF_SIZE);
        dn_class = 0;
        free(s_dp);
        free(s_ph);
        free(s_pq);
        free(s_pa);
        free(s_par);
        free(r_dp);
        free(r_ph);
        free(r_pq);
    }

    close(serv_sock);

    return 0;
}