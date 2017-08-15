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
        fprintf(stderr, "write file header fail\n");
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
        fprintf(stderr, "write pacaket header fail\n");
        return -1;
    }

    return 0;
}

unsigned int
pcap_write_packet_data(unsigned int fd, const unsigned char *data, unsigned int data_len)
{
    if (write(fd, data, data_len) != data_len) {
        fprintf(stderr, "write pacaket data fail\n");
        return -1;
    }
    return 0;
}

void
pcap_file_close(unsigned int fd)
{
    close(fd);
}