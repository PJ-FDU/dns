#include <stdlib.h>
#include <string.h>
#include "./dns_data_pack.h"

int addr2code(char code[], char addr[])
{
    int code_len = 0;
    for (int i = 0, last = 0; i < strlen(addr); i++)
    {
        if (addr[i] == '.')
        {
            int len = i - last;
            code[code_len++] = len;
            for (; last < i; last++)
                code[code_len++] = addr[last];
            last = i + 1;
        }
        else if (i == strlen(addr) - 1)
        {
            int len = i - last + 1;
            code[code_len++] = len;
            for (; last <= i; last++)
                code[code_len++] = addr[last];
        }
    }
    code[code_len++] = 0;
    return code_len;
}

void code2addr(char addr[], char code[], int code_len)
{
    int idx = 0;
    for (int i = 0; i < code_len;)
    {
        int len = code[i];
        if (len == 0)
            break;
        for (int j = 0; j < len; j++)
        {
            addr[idx++] = code[++i];
        }
        if (++i < code_len - 2)
            addr[idx++] = '.';
    }
}

int dnsPackage2code(char code[], DnsPackage *dnsPackage)
{
    int code_len = 0;
    if ((*dnsPackage).header)
    {
        code[code_len++] = (*(*dnsPackage).header).transaction_id / 0x100;
        code[code_len++] = (*(*dnsPackage).header).transaction_id % 0x100;
        code[code_len++] = (*(*dnsPackage).header).flags / 0x100;
        code[code_len++] = (*(*dnsPackage).header).flags % 0x100;
        code[code_len++] = (*(*dnsPackage).header).questions / 0x100;
        code[code_len++] = (*(*dnsPackage).header).questions % 0x100;
        code[code_len++] = (*(*dnsPackage).header).answer_rrs / 0x100;
        code[code_len++] = (*(*dnsPackage).header).answer_rrs % 0x100;
        code[code_len++] = (*(*dnsPackage).header).authority_rrs / 0x100;
        code[code_len++] = (*(*dnsPackage).header).authority_rrs % 0x100;
        code[code_len++] = (*(*dnsPackage).header).additional_rrs / 0x100;
        code[code_len++] = (*(*dnsPackage).header).additional_rrs % 0x100;
    }
    if ((*dnsPackage).queries)
    {
        char q_addr_code[BUF_SIZE] = {0};
        int q_addr_code_len = addr2code(q_addr_code, (*(*dnsPackage).queries).name);
        memcpy(code + code_len, q_addr_code, q_addr_code_len);
        code_len += q_addr_code_len;
        code[code_len++] = (*(*dnsPackage).queries).type / 0x100;
        code[code_len++] = (*(*dnsPackage).queries).type % 0x100;
        code[code_len++] = (*(*dnsPackage).queries).class_ / 0x100;
        code[code_len++] = (*(*dnsPackage).queries).class_ % 0x100;
    }
    if ((*dnsPackage).answers)
    {
        char a_addr_code[BUF_SIZE] = {0};
        int a_addr_code_len = addr2code(a_addr_code, (*(*dnsPackage).answers).name);
        memcpy(code + code_len, a_addr_code, a_addr_code_len);
        code_len += a_addr_code_len;
        code[code_len++] = (*(*dnsPackage).answers).type / 0x100;
        code[code_len++] = (*(*dnsPackage).answers).type % 0x100;
        code[code_len++] = (*(*dnsPackage).answers).class_ / 0x100;
        code[code_len++] = (*(*dnsPackage).answers).class_ % 0x100;
        code[code_len++] = (*(*dnsPackage).answers).time_to_live / 0x1000000;
        code[code_len++] = (*(*dnsPackage).answers).time_to_live % 0x1000000 / 0x10000;
        code[code_len++] = (*(*dnsPackage).answers).time_to_live % 0x1000000 % 0x10000 / 0x100;
        code[code_len++] = (*(*dnsPackage).answers).time_to_live % 0x1000000 % 0x10000 % 0x100;
        code[code_len++] = (*(*dnsPackage).answers).data_length / 0x100;
        code[code_len++] = (*(*dnsPackage).answers).data_length % 0x100;
        char ad_addr_code[BUF_SIZE] = {0};
        int ad_addr_code_len = addr2code(ad_addr_code, (*(*dnsPackage).answers).data);
        memcpy(code + code_len, ad_addr_code, ad_addr_code_len);
        code_len += ad_addr_code_len;
    }
    if ((*dnsPackage).additional_records)
    {
        char ar_addr_code[BUF_SIZE] = {0};
        int ar_addr_code_len = addr2code(ar_addr_code, (*(*dnsPackage).additional_records).name);
        memcpy(code + code_len, ar_addr_code, ar_addr_code_len);
        code_len += ar_addr_code_len;
        code[code_len++] = (*(*dnsPackage).additional_records).type / 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).type % 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).class_ / 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).class_ % 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).time_to_live / 0x1000000;
        code[code_len++] = (*(*dnsPackage).additional_records).time_to_live % 0x1000000 / 0x10000;
        code[code_len++] = (*(*dnsPackage).additional_records).time_to_live % 0x1000000 % 0x10000 / 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).time_to_live % 0x1000000 % 0x10000 % 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).data_length / 0x100;
        code[code_len++] = (*(*dnsPackage).additional_records).data_length % 0x100;
        char ard_addr_code[BUF_SIZE] = {0};
        int ard_addr_code_len = addr2code(ard_addr_code, (*(*dnsPackage).additional_records).data);
        memcpy(code + code_len, ard_addr_code, ard_addr_code_len);
        code_len += ard_addr_code_len;
    }
    return code_len;
}

void code2dnsPackage(DnsPackage *dnsPackage, char code[], int code_len)
{
    int idx = 0;
    (*(*dnsPackage).header).transaction_id = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
    (*(*dnsPackage).header).flags = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
    (*(*dnsPackage).header).questions = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
    (*(*dnsPackage).header).answer_rrs = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
    (*(*dnsPackage).header).authority_rrs = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
    (*(*dnsPackage).header).additional_rrs = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];

    if ((*(*dnsPackage).header).questions != 0)
    {
        char q_code[BUF_SIZE] = {0};
        int q_code_len = 0;
        for (; code[idx + q_code_len] != 0; q_code_len++)
            q_code[q_code_len] = code[idx + q_code_len];
        q_code[q_code_len++] = 0;
        code2addr((*(*dnsPackage).queries).name, q_code, q_code_len);
        idx += q_code_len;
        (*(*dnsPackage).queries).type = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).queries).class_ = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
    }

    if ((*(*dnsPackage).header).answer_rrs != 0)
    {
        char a_code[BUF_SIZE] = {0};
        int a_code_len = 0;
        for (; code[idx + a_code_len] != 0; a_code_len++)
            a_code[a_code_len] = code[idx + a_code_len];
        a_code[a_code_len++] = 0;
        code2addr((*(*dnsPackage).answers).name, a_code, a_code_len);
        idx += a_code_len;
        (*(*dnsPackage).answers).type = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).answers).class_ = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).answers).time_to_live \
            = (unsigned char)code[idx++] * 0x1000000 + (unsigned char)code[idx++] * 0x10000 \
            + (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).answers).data_length = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        char ad_code[BUF_SIZE] = {0};
        int ad_code_len = 0;
        for (; code[idx + ad_code_len] != 0; ad_code_len++)
            ad_code[ad_code_len] = code[idx + ad_code_len];
        ad_code[ad_code_len++] = 0;
        code2addr((*(*dnsPackage).answers).data, ad_code, ad_code_len);
        idx += ad_code_len;
    }

    if ((*(*dnsPackage).header).additional_rrs != 0)
    {
        char ar_code[BUF_SIZE] = {0};
        int ar_code_len = 0;
        for (; code[idx + ar_code_len] != 0; ar_code_len++)
            ar_code[ar_code_len] = code[idx + ar_code_len];
        ar_code[ar_code_len++] = 0;
        code2addr((*(*dnsPackage).additional_records).name, ar_code, ar_code_len);
        idx += ar_code_len;
        (*(*dnsPackage).additional_records).type = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).additional_records).class_ = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).additional_records).time_to_live \
            = (unsigned char)code[idx++] * 0x1000000 + (unsigned char)code[idx++] * 0x10000 \
            + (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        (*(*dnsPackage).additional_records).data_length = (unsigned char)code[idx++] * 0x100 + (unsigned char)code[idx++];
        char ard_code[BUF_SIZE] = {0};
        int ard_code_len = 0;
        for (; code[idx + ard_code_len] != 0; ard_code_len++)
            ard_code[ard_code_len] = code[idx + ard_code_len];
        ard_code[ard_code_len++] = 0;
        code2addr((*(*dnsPackage).additional_records).data, ard_code, ard_code_len);
        idx += ard_code_len;
    }
}

int char2intQC(char query_class_buf[])
{
    if(strcmp(query_class_buf, "IN") == 0) return IN;
    else return -1;
}

int char2intQT(char query_type_buf[])
{
    if(strcmp(query_type_buf, "A") == 0) return A;
    else if(strcmp(query_type_buf, "CNAME") == 0) return CNAME;
    else if(strcmp(query_type_buf, "MX") == 0) return MX;
    else return -1;
}

void int2charQC(char query_class_buf[], int qclass)
{
    if(qclass == 1) strcpy(query_class_buf, "IN");
    else memset(query_class_buf, 0, strlen(query_class_buf));
}

void int2charQT(char query_type_buf[], int qtype)
{
    if(qtype == A) strcpy(query_type_buf, "A");
    else if(qtype == CNAME) strcpy(query_type_buf, "CNAME");
    else if(qtype == MX) strcpy(query_type_buf, "MX");
    else memset(query_type_buf, 0, strlen(query_type_buf));
}