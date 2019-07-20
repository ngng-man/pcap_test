#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

bool check_packet(const uint8_t* packet) {
    if (packet[12] == 0x08 && packet[13] == 0x00) {
        if (packet[23] == 0x06) {
            printf("\n----------------------------------------\n");
            printf("Ethernet Protocol Type : IPv4\n");
            printf("IP Protocol Type : TCP\n");
            return true;
        }
    };
    return false;
}

int ip_header_check(const uint8_t* packet) {
    return (packet[14] % 16 * 4);
}

int tcp_header_check(const uint8_t* packet, int i) {
    return (packet[14+i+12] / 4);
}

void print_mac(const uint8_t* mac) {
    printf("MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const uint8_t* ip) {
    printf("IP : %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const uint8_t* port) {
    printf("Port : %u\n", (port[0] << 8) | port[1]);
}

void print_tcp_data(const uint8_t* packet, int i, int j) {
    int data_size = j - 20;
    if(data_size > 10)
        data_size = 10;
    printf("---------------TCP Data---------------\n");
    for(int n = 0; n < data_size; n++)
        printf("%02X ", packet[14 + i + 20 + n]);
    printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    if (check_packet(packet)) {
        int ethernet_header_size = 14;
        int ip_header_size = ip_header_check(packet);
        int tcp_header_size = tcp_header_check(packet, ip_header_size);
        //printf("%d\n", ip_header_size);
        //printf("%d\n", tcp_header_size);

        printf("\n[Source Info]\n");
        print_mac(packet + 6);
        print_ip(packet + ethernet_header_size + 12);
        print_port(packet + ethernet_header_size + ip_header_size);

        printf("\n[Destination Info]\n");
        print_mac(packet);
        print_ip(packet + ethernet_header_size + 16);
        print_port(packet + ethernet_header_size + ip_header_size + 2);

        if(tcp_header_size > 20)
            print_tcp_data(packet, ip_header_size, tcp_header_size);
    }
  }

  pcap_close(handle);
  return 0;
}
