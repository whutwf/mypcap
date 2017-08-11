#include "pcap.h"

/**
 * 扩展文件大小
 * @return int 之前文件的大小
 */
static int
p_mmap_ftruncate(int fd, int length)
{
    int size = 0;
    struct stat sta;

    //得到文件大小，文件记录条数
    fstat(fd, &sta);
    size = sta.st_size;
    fprintf(stdout, "file size is %d\n", size);
    ftruncate(fd, size + length);

    return size;
}

int
p_mmap_file_addr(const char *path)
{
    int fd;
    size_t n;
    if ((fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0) {
        fprintf(stderr, "Error: open file failed: (errno = %d) %s\n", errno, strerror(errno));
        return -1;
    }

    return fd;
}

void
p_mmap_write_file_header(int fd)
{
    if (fd == -1) {
        return;
    }

    struct pcap_file_header *p_mmap;
    int before_fsize;
    int current_fsize;

    unsigned int file_header_size = sizeof(struct pcap_file_header);
    before_fsize = p_mmap_ftruncate(fd, file_header_size);
    current_fsize = before_fsize + file_header_size;
    p_mmap = (struct pcap_file_header *)mmap(0, current_fsize, PROT_READ | PROT_WRITE,
             MAP_SHARED, fd, 0);
    p_mmap += before_fsize;

    p_mmap->magic = TCPDUMP_MAGIC;
    p_mmap->version_major = PCAP_VERSION_MAJOR;
    p_mmap->version_minor = PCAP_VERSION_MINOR;
    p_mmap->thiszone = 0;
    p_mmap->sigfigs = 0;
    p_mmap->snaplen = PCAP_SNAPLEN;
    p_mmap->linktype = PCAP_LINKTYPE;

    printf("%d\n", p_mmap->thiszone);
    munmap(p_mmap, current_fsize);
}

void
p_mmap_write_packet_header(int fd, int data_len)
{
    if (fd == -1) {
        return;
    }

    struct pcap_packet_header *p_mmap;
    int before_fsize;
    int current_fsize;

    struct timeval tv;
    unsigned int phead_size = sizeof(struct pcap_packet_header);

    before_fsize = p_mmap_ftruncate(fd, phead_size);
    current_fsize = before_fsize + phead_size;
    p_mmap = (struct pcap_packet_header *)mmap(0, current_fsize, PROT_READ | PROT_WRITE,
             MAP_SHARED, fd, 0);
    p_mmap += before_fsize;


    gettimeofday(&tv, NULL);
    p_mmap->tv_sec = tv.tv_sec;
    p_mmap->tv_usec = tv.tv_usec;
    p_mmap->caplen = data_len;
    p_mmap->len = data_len;

    munmap(p_mmap, current_fsize);
}
void
p_mmap_write_packet_data(int fd, const unsigned char *data, int data_len)
{
    if (fd == -1) {
        return;
    }

    char *p_mmap;
    int before_fsize;
    int current_fsize;

    before_fsize = p_mmap_ftruncate(fd, data_len);
    current_fsize = before_fsize + data_len;
    p_mmap = (char *)mmap(0, current_fsize, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, 0);
    p_mmap += before_fsize;

    memcpy(p_mmap, data, data_len);
    munmap(p_mmap, current_fsize);
}