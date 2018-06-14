#ifndef DNS_DATA_PACK_H
#define DNS_DATA_PACK_H

#define BUF_SIZE 1000

#define A 1
#define CNAME 5
#define MX 15

#define IN 1

typedef struct PackageHeader
{
    unsigned short transaction_id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answer_rrs;
    unsigned short authority_rrs;
    unsigned short additional_rrs;
} PackageHeader;

typedef struct PackageQueries
{
    char name[BUF_SIZE];
    unsigned short type;
    unsigned short class_;
} PackageQueries;

typedef struct PackageAnswers
{
    char name[BUF_SIZE];
    unsigned short type;
    unsigned short class_;
    unsigned int time_to_live;
    unsigned short data_length;
    char data[BUF_SIZE];
} PackageAnswers;

typedef struct PackageAdditionalRecords
{
    char name[BUF_SIZE];
    unsigned short type;
    unsigned short class_;
    unsigned int time_to_live;
    unsigned short data_length;
    char data[BUF_SIZE];
} PackageAdditionalRecords;

typedef struct DnsPackage
{
    PackageHeader *header;
    PackageQueries *queries;
    PackageAnswers *answers;
    PackageAdditionalRecords *additional_records;
} DnsPackage;

typedef struct RR
{
    char dn[BUF_SIZE];
    int ttl;
    int qc;
    int qt;
    char data[BUF_SIZE];
} RR;

int addr2code(char code[], char addr[]);
void code2addr(char addr[], char code[], int code_len);
int dnsPackage2code(char code[], DnsPackage *dnsPackage);
void code2dnsPackage(DnsPackage *dnsPackage, char code[], int code_len);

int char2intQC(char query_class_buf[]);
int char2intQT(char query_type_buf[]);
void int2charQC(char query_class_buf[], int qclass);
void int2charQT(char query_type_buf[], int qtype);

#endif
