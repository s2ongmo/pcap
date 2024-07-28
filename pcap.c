#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>

// 사용법을 출력하는 함수
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

// 프로그램 매개변수를 저장하는 구조체
typedef struct {
    char* dev_;  // 네트워크 인터페이스 이름
} Param;

Param param = {
    .dev_ = NULL  // 초기값 NULL
};

// 명령줄 인자를 파싱하는 함수
bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {  // 인자가 2개가 아닌 경우
        usage();  // 사용법 출력
        return false;  // 실패 반환
    }
    param->dev_ = argv[1];  // 네트워크 인터페이스 이름 설정
    return true;  // 성공 반환
}

// 데이터를 16진수로 출력하는 함수
void print_hex(const u_char* data, int len) {
    for (int i = 0; i < len && i < 20; i++) {  // 최대 20바이트 출력
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// 프로그램의 메인 함수
int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))  // 명령줄 인자 파싱
        return -1;  // 실패 시 종료

    char errbuf[PCAP_ERRBUF_SIZE];  // 에러 메시지 버퍼
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);  // 네트워크 인터페이스 열기
    if (pcap == NULL) {  // 실패 시
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);  // 에러 메시지 출력
        return -1;  // 종료
    }

    while (true) {
        struct pcap_pkthdr* header;  // 패킷 헤더
        const u_char* packet;  // 패킷 데이터
        int res = pcap_next_ex(pcap, &header, &packet);  // 다음 패킷 읽기
        if (res == 0) continue;  // 타임아웃 시 계속
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {  // 에러 발생 시
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));  // 에러 메시지 출력
            break;  // 루프 종료
        }

        // 이더넷 헤더
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        // IPv4 헤더
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

        if (ip_hdr->ip_p != IPPROTO_TCP) {  // TCP 프로토콜이 아닌 경우
            continue;  // 무시
        }

        // TCP 헤더
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4));
        // 페이로드 데이터
        const u_char* payload = packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
        int payload_len = header->caplen - (payload - packet);  // 페이로드 길이

        printf("%u bytes captured\n", header->caplen);  // 캡처된 바이트 수 출력

        // 이더넷 헤더 정보 출력
        printf("Ethernet Header\n");
        printf("ㄴSource MAC Address      : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf("ㄴDestination MAC Address : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

        // IP 헤더 정보 출력
        printf("IP Header\n");
        printf("ㄴsource IP Address       : %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("ㄴDestination IP Address  : %s\n", inet_ntoa(ip_hdr->ip_dst));
        printf("ㄴProtocol                : %u\n", (unsigned int)ip_hdr->ip_p);

        // TCP 헤더 정보 출력
        printf("TCP Header\n");
        printf("ㄴSource Port             : %u\n", ntohs(tcp_hdr->th_sport));
        printf("ㄴDestination Port        : %u\n", ntohs(tcp_hdr->th_dport));

        // 페이로드 데이터 출력 (최대 20바이트)
        printf("Payload (first 20 bytes):\n");
        print_hex(payload, payload_len);

        printf("\n");  // 줄 바꿈
    }

    pcap_close(pcap);  // pcap 세션 닫기
    return 0;  // 프로그램 종료
}
