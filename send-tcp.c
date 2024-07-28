#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>

int main() {
    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];
    char payload[1024];

    // Initialize libnet
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return 1;
    }

    // Read payload from stdin
    if (fgets(payload, sizeof(payload), stdin) == NULL) {
        fprintf(stderr, "Error reading payload\n");
        libnet_destroy(l);
        return 1;
    }

    // Example code to build a TCP packet
    uint32_t dest_ip = libnet_name2addr4(l, "192.168.0.1", LIBNET_RESOLVE);
    uint32_t src_ip = libnet_name2addr4(l, "192.168.0.2", LIBNET_RESOLVE);
    uint16_t src_port = 12345;
    uint16_t dest_port = 80;

    libnet_build_tcp(
        src_port, // source port
        dest_port, // destination port
        0, // sequence number
        0, // acknowledgment number
        TH_SYN, // control flags
        1024, // window size
        0, // checksum (0 for libnet to autofill)
        0, // urgent pointer
        LIBNET_TCP_H + strlen(payload), // total length of the TCP packet
        (uint8_t*)payload, // payload
        strlen(payload), // payload size
        l, // libnet context
        0 // packet id (0 for new packet)
    );

    // Build the IP layer
    libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + strlen(payload), // length
        0, // TOS
        0, // IP ID
        0, // IP Frag
        64, // TTL
        IPPROTO_TCP, // protocol
        0, // checksum (0 for libnet to autofill)
        src_ip, // source IP
        dest_ip, // destination IP
        NULL, // payload
        0, // payload size
        l, // libnet context
        0 // packet id (0 for new packet)
    );

    // Write the packet to the network
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    // Clean up libnet
    libnet_destroy(l);

    return 0;
}
