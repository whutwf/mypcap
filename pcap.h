#ifndef __PCAP_H__
#define __PCAP_H__

#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include<sys/stat.h>
// #include <stdlib.h>

#define TCPDUMP_MAGIC   0xa1b2c3d4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_LINKTYPE	1
#define PCAP_SNAPLEN	0x0000ffff	//逆序记载0xffff0000
#define MMAP_PAGE_SIZE	65535

/*
typedef signed char u_char8_t;
typedef signed short u_int16_t;
typedef signed int u_int32_t;
typedef signed long long u_int64_t;
typedef unsigned char u_uchar8_t;
typedef unsigned short u_uint16_t;
typedef unsigned int u_uint32_t;
typedef unsigned long long u_uint64_t;
typedef unsigned long u_word_t;*/

#ifdef __cplusplus
extern "C" {
#endif

struct pcap_file_header {
    unsigned int magic;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;	/* gmt to local correction */
    unsigned int sigfigs;	/* accuracy of timestamps */
    unsigned int snaplen;	/* max length saved portion of each pkt */
    unsigned int linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_packet_header {
    unsigned int tv_sec;        /* Seconds. */
    unsigned int tv_usec;  /* Microseconds. */
    unsigned int caplen;		/* length of portion present */
    unsigned int len;		/* length this packet (off wire) */
};

int
p_mmap_file_addr(const char *path);

void
p_mmap_write_file_header(int fd);

void
p_mmap_write_packet_header(int fd, int data_len);

void
p_mmap_write_packet_data(int fd, const unsigned char *data, int data_len);

void
p_munmap(void *p_mmap, int page_length);


unsigned int
pcap_file_open(const char *pcap_file_name);

unsigned int
pcap_write_file_header(unsigned int fd);

unsigned int
pcap_write_packet_header(unsigned int fd, unsigned int data_len);

unsigned int
pcap_write_packet_data(unsigned int fd, const unsigned char *data, unsigned int data_len);

void
pcap_file_close(unsigned int fd);

#ifdef __cplusplus
}
#endif
#endif