#include <pcap.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <thread>
#include "syn_flood_detector.h"
#include "udpEntropyCusumDetector.h"
#include "HttpDetector.h"
#pragma comment(lib, "ws2_32.lib")

using namespace std;

// Ethernet header
struct ether_header
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

// IP header
struct ip_header
{
    unsigned char ip_header_len : 4;
    unsigned char ip_version : 4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    unsigned int ip_src;
    unsigned int ip_dst;
};

// TCP header
struct tcp_header
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset : 4;
    unsigned char reserved : 4;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

// Struct holding pointers to all detectors
struct Detectors {
    UdpEntropyCusumDetector* udpDetector;
    SYNFloodDetector* synDetector;
    HttpDetector* httpDetector;
};

// Get current timestamp
string getTimestamp()
{
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return string(buf);
}

// Packet handler called by pcap_loop
void packetHandler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    Detectors* detectors = reinterpret_cast<Detectors*>(user);

    const struct ether_header *ethHeader = (struct ether_header *)packet;
    if (ntohs(ethHeader->ether_type) != 0x0800) return; // Only IPv4

    const struct ip_header *ipHeader = (struct ip_header *)(packet + sizeof(struct ether_header));
    int ip_header_length = ipHeader->ip_header_len * 4;

    struct in_addr src, dst;
    src.s_addr = ipHeader->ip_src;
    dst.s_addr = ipHeader->ip_dst;
    std::string srcIP = inet_ntoa(src);
    std::string dstIP = inet_ntoa(dst);
    int size = pkthdr->len;

    std::string timestamp = getTimestamp();

   if (ipHeader->ip_protocol == IPPROTO_TCP)
{
    const struct tcp_header *tcpHeader = (struct tcp_header *)(packet + sizeof(struct ether_header) + ip_header_length);
    unsigned short src_port = ntohs(tcpHeader->src_port);
    unsigned short dst_port = ntohs(tcpHeader->dst_port);

    bool isSyn = (tcpHeader->flags & 0x02) != 0;
    bool isAck = (tcpHeader->flags & 0x10) != 0;

    // SYN Flood Detector call
    if (detectors->synDetector)
    {
        detectors->synDetector->processPacket(srcIP, dstIP, isSyn, isAck);
        // if (isSyn)
        //     std::cout << "[" << timestamp << "] SYN Packet | " << srcIP << ":" << src_port << " -> " << dstIP << ":" << dst_port << std::endl;
    }

    // HTTP/HTTPS Detector call for ports 80 (HTTP) and 443 (HTTPS)
    if (detectors->httpDetector && (src_port == 80 || dst_port == 80 || src_port == 443 || dst_port == 443))
    {
        detectors->httpDetector->processPacket(srcIP, dstIP, src_port, dst_port, size);
        // std::cout << "[" << timestamp << "] HTTP(S) Packet | " << srcIP << ":" << src_port << " -> " << dstIP << ":" << dst_port << std::endl;
    }
}
else if (ipHeader->ip_protocol == IPPROTO_UDP)
{
    if (detectors->udpDetector)
    {
        detectors->udpDetector->update(srcIP, 0); // Assuming 0 is a dummy parameter for your update method
        // std::cout << "[" << timestamp << "] UDP Packet | " << srcIP << " -> " << dstIP << std::endl;
    }
}

}

// Capture packets on a single device
void captureOnDevice(const char *deviceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        cerr << "Failed to open device " << deviceName << ": " << errbuf << endl;
        return;
    }

    UdpEntropyCusumDetector udpDetector;
    SYNFloodDetector synDetector;
    HttpDetector httpDetector;

    Detectors detectors{ &udpDetector, &synDetector, &httpDetector };

    cout << "Capturing on device: " << deviceName << endl;

    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char *>(&detectors));

    pcap_close(handle);
}

// Capture on all devices with multithreading
void startLiveCaptureAllDevices()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cerr << "Error finding devices: " << errbuf << endl;
        return;
    }

    vector<thread> threads;
    pcap_if_t *device = alldevs;

    while (device)
    {
        cout << "Found device: " << device->name << " ("
             << (device->description ? device->description : "No description") << ")" << endl;

        // Launch capture in a thread for each device
        string devName(device->name);
        threads.emplace_back([devName]()
                             { captureOnDevice(devName.c_str()); });

        device = device->next;
    }

    for (auto &t : threads)
    {
        t.join();
    }

    pcap_freealldevs(alldevs);
}
