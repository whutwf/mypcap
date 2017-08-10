#include "pcap.h"

int
p_mmap_file_addr(const char *path, void **p_mmap, int page_length)
{
    int fd;
    size_t n;
    if ((fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
        fprintf(stderr, "Error: open file failed: (errno = %d) %s\n", errno, strerror(errno));
        return -1;
    }

    n = write(fd, "\0", 1);
    if (n < 0) {
        fprintf(stderr, "Error: Init to write mmap file failed: (errno = %d) %s\n", errno, strerror(errno));
        return -2;
    }

    p_mmap = mmap(0, page_length, PROT_READ | PROT_WRITE, MAP_SHARED,fd, 0);
    if (p_mmap == MAP_FAILED) {
        fprintf(stderr, "Error: mmap file failed: (errno = %d) %s\n", errno, strerror(errno));
        close(fd);
        return -3;
    }

    close(fd);
    fprintf(stdout, "mmaped file to memory, size = %d\n", page_length);

    return 0;
}

void
p_mmap_write_file_header(void **p_mmap)
{
    if (p_mmap == NULL) {
        fprintf(stderr, "Error: the p_mmap point is null\n");
        return;
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


    fprintf(stdout, "file header, size = %d\n", file_header_size);
    // // msync
    memset(&head, 0, file_header_size);
    memcpy(&p_mmap, &head, file_header_size);

    p_mmap += file_header_size;

}

void
p_mmap_write_packet_header(void **p_mmap, int data_len)
{
    if (p_mmap == NULL) {
        fprintf(stderr, "Error: the p_mmap point is null\n");
        return;
    }

    unsigned int phead_size = sizeof(struct pcap_packet_header);
    struct pcap_packet_header phead;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    phead.tv_sec = tv.tv_sec;
    phead.tv_usec = tv.tv_usec;
    phead.caplen = data_len;
    phead.len = phead.caplen;

    memset(&phead, 0, phead_size);
    memcpy(&p_mmap, &phead, phead_size);
    p_mmap += phead_size;
}
void
p_mmap_write_packet_data(void **p_mmap, const unsigned char *data, int data_len)
{
    if (p_mmap == NULL) {
        fprintf(stderr, "Error: the p_mmap point is null\n");
        return;
    }

    memset(data, 0, data_len);
    memcpy(&p_mmap, data, data_len);
    p_mmap += data_len;
}

void
p_munmap(void *p_mmap, int page_length)
{
    munmap(p_mmap, page_length);
}