#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include "live_capture.h" // your detector class
#include "syn_flood_detector.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_srcip;
    unsigned int       iph_destip;
};

struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    unsigned char      tcph_flags;
    unsigned short int tcph_window;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

#define ETHERNET_HEADER_SIZE 14

void packetHandler(u_char* param, const pcap_pkthdr* header, const u_char* pkt_data) {
    const ipheader* ipHeader = (ipheader*)(pkt_data + ETHERNET_HEADER_SIZE);

    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->iph_srcip), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->iph_destip), dstIP, INET_ADDRSTRLEN);

    int ipHeaderLength = (ipHeader->iph_ihl * 4);
    const tcpheader* tcpHeader = (tcpheader*)(pkt_data + ETHERNET_HEADER_SIZE + ipHeaderLength);

    bool synFlag = (tcpHeader->tcph_flags & 0x02) != 0;
    bool ackFlag = (tcpHeader->tcph_flags & 0x10) != 0;

    extern SYNFloodDetector synDetector;  // assuming defined globally in another file

    synDetector.processPacket(srcIP, dstIP, synFlag, ackFlag);
}

void captureOnDevice(const char* deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Failed to open device: " << deviceName << endl;
        return;
    }

    cout << "Capturing on device: " << deviceName << "...\n";

    pcap_loop(handle, 0, packetHandler, NULL);
    pcap_close(handle);
}

void startLiveCaptureAllDevices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return;
    }

    vector<thread> threads;
    pcap_if_t* device = alldevs;

    while (device) {
        cout << "Found device: " << device->name << " (" 
             << (device->description ? device->description : "No description") << ")" << endl;

        // Create a thread for each device
        string devName(device->name);
        threads.emplace_back([devName]() {
            captureOnDevice(devName.c_str());
        });

        device = device->next;
    }

    for (auto& t : threads) {
        t.join();  // Let each thread capture indefinitely
    }

    pcap_freealldevs(alldevs);
}
