#include "pcap.h"

unsigned int
pcap_file_open(const char *pcap_file_name)
{
    unsigned int fd = open(pcap_file_name, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "can't open %s\n", pcap_file_name);
    }

    return fd;
}

unsigned int
pcap_write_file_header(unsigned int fd)
{
    if (fd == -1) {
        return -1;
    }
    unsigned int file_header_size = sizeof(struct pcap_file_header);
    struct pcap_file_header head;
    head.magic = TCPDUMP_MAGIC;
    head.version_major = PCAP_VERSION_MAJOR;
    head.version_minor = PCAP_VERSION_MINOR;
    head.thiszone = 0;
    head.sigfigs = 0;
    head.snaplen = PCAP_SNAPLEN;
    head.linktype = PCAP_LINKTYPE;

    if (write(fd, &head, file_header_size) !=file_header_size) {
        perror("Error: write file header\n");
        return -1;
    }

    return 0;
}

unsigned int
pcap_write_packet_header(unsigned int fd, unsigned int data_len)
{
    unsigned int phead_size = sizeof(struct pcap_packet_header);
    struct pcap_packet_header phead;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    phead.tv_sec = tv.tv_sec;
    phead.tv_usec = tv.tv_usec;
    phead.caplen = data_len;
    phead.len = phead.caplen;

    if (write(fd, &phead, phead_size) != phead_size) {
        perror("Error: write pacaket header\n");
        return -1;
    }

    return 0;
}

unsigned int
pcap_write_packet_data(unsigned int fd, const unsigned char *data, unsigned int data_len)
{
    if (write(fd, data, data_len) != data_len) {
        perror("Error: write pacaket data\n");
        return -1;
    }
    return 0;
}

static void ethernet_set_misc(int sockfd, struct ifreq *ethreq, const char *eth_name) {

    if (ioctl(sockfd, SIOCGIFFLAGS, &ethreq) < 0) {
        perror("Error: get interface flags\n");
    } else {
        ethreq->ifr_flags |=IFF_PROMISC;
    }

    if (ioctl(sockfd, SIOCSIFFLAGS, &ethreq) < 0) {
        perror("Error: set interface flags\n");
    }
}

void
buf_print(const char *buf, int n) {
    int i;
    for(i=0; i<n; i++) {
        if( i % 16 == 0) printf("\n%04d: ", i);
        else if(i % 8 == 0) printf(" ");
        fprintf(stdout, "%02x ", buf[i] & 0xff);
    }
    fprintf(stdout, " %04d\n", n);
}

static int
ethernet_bind(const char *eth_name)
{
    struct ifreq ethreq;
    struct sockaddr_ll saddr_ll;

    int sockfd = -1;
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Error: receive data sock create\n");
        return -1;
    } else {
        bzero(&saddr_ll, sizeof(saddr_ll));
        memcpy(ethreq.ifr_name, eth_name, strlen(eth_name));
        ethernet_set_misc(sockfd, &ethreq, eth_name);
        if(ioctl(sockfd, SIOCGIFINDEX, &ethreq) < 0) {
            perror("Error: get interface index\n");
            close(sockfd);
            return -1;
        }

        saddr_ll.sll_family = PF_PACKET;
        saddr_ll.sll_ifindex = ethreq.ifr_ifindex;
        saddr_ll.sll_protocol = htons(ETH_P_ALL);

        sockfd = (bind(sockfd, (struct sockaddr *)&saddr_ll, sizeof(saddr_ll)) < 0) ? -1 : sockfd;

        return sockfd;
    }
}

int
ethernet_data_fetch(unsigned char *recv_buffer, const char *eth_name, const char *pcap_file_name)
{

    int sockfd = -1;
    if ((sockfd = ethernet_bind(eth_name)) < 0) {
        perror("Error:ethernet_bind\n");
        return -1;
    } else {
        int recv_length = 0;
        int filefd = pcap_file_open(pcap_file_name);

        if (filefd > 0) {
            pcap_write_file_header(filefd);
            while (1) {
                recv_length = recvfrom(sockfd, recv_buffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
                pcap_write_packet_header(filefd, recv_length);
                pcap_write_packet_data(filefd, recv_buffer, recv_length);

                buf_print(recv_buffer, recv_length);
            }

            pcap_file_close(sockfd);
        } else {
            perror("Error: create pmap file\n");
            return -1;
        }

        return 0;
    }
}