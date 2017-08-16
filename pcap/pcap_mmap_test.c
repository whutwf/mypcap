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
    void *p_mmap;
    const char *pcap_file_name = "pcap_test_three.pcap";
    const char *eth_name = "eno1";
    unsigned char recv_buffer[RECV_BUFFER_SIZE];

    if (ethernet_data_fetch(recv_buffer, eth_name, pcap_file_name) < 0) {
        return -1;
    }

    return 0;
}