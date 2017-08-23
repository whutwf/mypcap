#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

int main()
{
    const char *pcap_file_name = "pcap_test_three.pcap";
    const char *eth_name = "eno1";
#define PCAP_READ
#ifdef PCAP_CREAT
    unsigned char recv_buffer[RECV_BUFFER_SIZE];

    if (ethernet_data_fetch(recv_buffer, eth_name, pcap_file_name) < 0) {
        return -1;
    }
#endif

#ifdef PCAP_READ
    struct pcap_file_hdr pf_hdr;
    struct pcap_packet_hdr pkt_hdr;
    struct ethernet_hdr *eth_hdr;
    unsigned char packets[RECV_BUFFER_SIZE];
    int fd = -1;
    int n = 0;
    fd = open(pcap_file_name, O_RDONLY);
    if (fd < 0) {
        fprintf(stdout, "[TEST] Error: open pcap %s\n", pcap_file_name);
        return -1;
    }

    if (read(fd, &pf_hdr, sizeof(pf_hdr)) < sizeof(pf_hdr)) {
        perror("[TEST] Error: read pcap file header\n");
        return -1;
    }

    fprintf (stdout, "---------print file header---------\n");
    pcap_file_hdr_print(&pf_hdr);

    while (n < PCAP_SNAPLEN) {
        if (read(fd, &pkt_hdr, sizeof(pkt_hdr)) < sizeof(pkt_hdr)) {
            perror("[TEST] Error: read pcap packet header\n");
            break;
        }
        fprintf (stdout, "---------print packet header---------\n");
        fprintf (stdout, "tv_sec = %u\n", pkt_hdr.tv_sec);
        fprintf (stdout, "tv_usec = %u\n", pkt_hdr.tv_usec);
        fprintf (stdout, "caplen = %u\n", pkt_hdr.caplen);
        fprintf (stdout, "len = %u\n", pkt_hdr.len);

        if (read(fd, packets, pkt_hdr.caplen) < pkt_hdr.caplen) {
            perror("[TEST] Error: read pcap packet\n");
            return -1;
        }
        // buf_print(packets, pkt_hdr.caplen);
        pcap_parser(packets);
    }

#endif

    return 0;
}