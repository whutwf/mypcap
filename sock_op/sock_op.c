#include "sock_op.h"

static void
add_ifi_info(char *ifi_name, struct sockaddr *ifi_addr, struct ifi_info **head)
{
    struct ifi_info *ifi_info_ptr = (struct ifi_info *)calloc(1, sizeof(struct ifi_info));
    if (ifi_info_ptr == NULL) {
        fprintf(stderr, "Error: can't create ifi_info node\n");
        return;
    }

    memcpy(ifi_info_ptr->ifi_name, ifi_name, strlen(ifi_name));
    ifi_info_ptr->ifi_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
    if (ifi_info_ptr->ifi_addr == NULL) {
        fprintf(stderr, "Error: can't create ifi_info_ptr->ifi_addr member\n");
        return;
    }
    ifi_info_ptr->ifi_addr = ifi_addr;
    ifi_info_ptr->ifi_next = NULL;
    *head = ifi_info_ptr;
}

static void
print_ifi_info(struct ifi_info *head)
{
    if (head == NULL) {
        fprintf(stdout, "ifi_info is none\n");
        return;
    }

    struct ifi_info *ptr = head;
    while (ptr != NULL) {
        fprintf(stdout, "name = [%s]\n" , ptr->ifi_name);
        fprintf(stdout, "local addr = [%s]\n" ,inet_ntoa(((struct sockaddr_in*)&(ptr->ifi_addr))->sin_addr));
        ptr = ptr->ifi_next;
    }
}

struct ifi_info *
get_ifi_info(int family)
{
    struct ifi_info *head = NULL;

    int i=0;
    int sockfd = -1;
    struct ifconf ifconf;
    unsigned char buf[IFC_LEN];
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
    for (i=(ifconf.ifc_len/sizeof (struct ifreq)); i>0; i--)
    {
        add_ifi_info(ifreq->ifr_name, &ifreq->ifr_addr, &head);
        printf("name = [%s]\n" , ifreq->ifr_name);
        printf("local addr = [%s]\n" ,inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr));
        ifreq++;
    }

    return head;
}

int main()
{
    struct ifi_info *head = get_ifi_info(1);
    if (head == NULL) {
        printf(":wangfei\n");
    }

    print_ifi_info(head);
}