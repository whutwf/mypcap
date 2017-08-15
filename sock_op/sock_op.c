#include "sock_op.h"

void
add_ifi_info(const char *ifi_name, struct sockaddr *ifi_addr, struct ifi_info **head)
{
    // fprintf(stdout, "name = [%s]\n" , ifi_name);
    // fprintf(stdout, "local addr = [%s]\n" ,inet_ntoa(((struct sockaddr_in*)(ifi_addr))->sin_addr));
    if (ifi_addr == NULL || ifi_name == NULL) {
        fprintf(stderr, "Error: ifi_addr is NULL or ifi_name is NULL\n");
        return;
    }

    struct ifi_info *ifi_info_ptr = calloc(1, sizeof(struct ifi_info));
    if (ifi_info_ptr == NULL) {
        fprintf(stderr, "Error: can't create ifi_info node\n");
        return;
    }

    memcpy(ifi_info_ptr->ifi_name, ifi_name, IFI_NAME);
    ifi_info_ptr->ifi_addr = calloc(1, sizeof(struct sockaddr_in));
    if (ifi_info_ptr->ifi_addr == NULL) {
        fprintf(stderr, "Error: can't create ifi_info_ptr->ifi_addr member\n");
        return;
    }
    memcpy(ifi_info_ptr->ifi_addr, ifi_addr, sizeof(struct sockaddr_in));
    // ifi_info_ptr->ifi_addr = ifi_addr;   //赋值指针有问题，后边想想
    ifi_info_ptr->ifi_next = *head;
    *head = ifi_info_ptr;
}

void
print_ifi_info(struct ifi_info *head)
{
    if (head == NULL) {
        fprintf(stdout, "ifi_info is none\n");
        return;
    }

    struct ifi_info *ptr = head;
    while (ptr != NULL) {
        fprintf(stdout, "name = [%s]\n" , ptr->ifi_name);
        fprintf(stdout, "local addr = [%s]\n" ,inet_ntoa(((struct sockaddr_in*)(ptr->ifi_addr))->sin_addr));
        ptr = ptr->ifi_next;

    }
}

void
free_ifi_info(struct ifi_info *head)
{
    struct ifi_info *ifi, *ifi_next;

    for (ifi = head; ifi != NULL; ifi = ifi_next) {
        if (ifi->ifi_addr != NULL) {
            free(ifi->ifi_addr);
        }
        ifi_next = ifi->ifi_next;
        free(ifi);
    }
}

struct ifi_info *
get_ifi_info(int family)
{
    struct ifi_info *head = NULL;

    int i=0;
    int sockfd = -1;
    struct ifconf ifconf;
    char buf[IFC_LEN];
    struct ifreq *ifreq;

    ifconf.ifc_len = IFC_LEN;
    ifconf.ifc_buf = buf;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Error: socket get failed\n");
        return head;
    }

    ioctl(sockfd, SIOCGIFCONF, &ifconf); //get all the ifconfig info

    ifreq = (struct ifreq*)buf;
    for (i = (ifconf.ifc_len / sizeof (struct ifreq)); i > 0; --i)
    {
        add_ifi_info(ifreq->ifr_name, &ifreq->ifr_addr, &head);
        ++ifreq;
    }

    return head;
}