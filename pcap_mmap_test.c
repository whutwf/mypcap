#include "pcap.h"

int main()
{
    void *p_mmap;
    const char *pcap_file_name = "pcap_test_three.pcap";
    const unsigned char data[102] = {0x00, 0x32 ,0x50 ,0x91 ,0x33 ,0x20 ,0xA2 ,0xE0 ,0x12 ,0xFA ,
                                     0xBF ,0x63 ,0x81 ,0x00 ,0x00 ,0x0A ,0x08 ,0x00 ,0x45 ,0x00 ,
                                     0x00, 0x54, 0x00 ,0x00 ,0x40 ,0x00 ,0x40 ,0x01 ,0x12 ,0x9E ,
                                     0x0A ,0x04 ,0x05 ,0x02 ,0x14 ,0x04 ,0x05 ,0x02 ,0x08 ,0x00 ,
                                     0xDC ,0xED, 0xBA, 0x6D ,0x03 ,0xB4 ,0xF0 ,0x62 ,0x98 ,0x57 ,
                                     0x00 ,0x00 ,0x00 ,0x00 ,0x09 ,0x63 ,0x0C ,0x00 ,0x00 ,0x00 ,
                                     0x00 ,0x00 ,0x10, 0x11, 0x12 ,0x13 ,0x14 ,0x15 ,0x16 ,0x17 ,
                                     0x18 ,0x19 ,0x1A ,0x1B ,0x1C ,0x1D ,0x1E ,0x1F ,0x20 ,0x21 ,
                                     0x22 ,0x23 ,0x24 ,0x25, 0x26, 0x27 ,0x28 ,0x29 ,0x2A ,0x2B ,
                                     0x2C ,0x2D ,0x2E ,0x2F ,0x30 ,0x31 ,0x32 ,0x33 ,0x34 ,0x35 ,
                                     0x36 ,0x37
                                    };

    int i = 5;

    int fd = p_mmap_file_addr(pcap_file_name);

    if (fd != -1) {
        p_mmap_write_file_header(fd);
        // while(i--) {
        p_mmap_write_packet_header(fd, 102);
        // p_mmap_write_packet_data(fd, data, 102);
        // }

        close(fd);
    }

    // int fd = pcap_file_open(pcap_file_name);
    // if (fd != -1) {
    //     pcap_write_file_header(fd);
    //     while (i--) {
    //         // pcap_write_packet_header(fd, 102);
    //         // pcap_write_packet_data(fd, data, 102);
    //     }
    // }

    return 0;
}