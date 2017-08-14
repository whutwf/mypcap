#ifndef PCAP_SOCK_OP_H__
#define PCAP_SOCK_OP_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <net/if.h>

#define IFI_NAME    16
#define IFC_LEN     1024

struct ifi_info {
    char ifi_name[IFI_NAME];
    struct sockaddr *ifi_addr;
    struct ifi_info *ifi_next;
};
#ifdef __cplusplus
}
#endif
#endif