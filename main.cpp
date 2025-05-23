#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <iostream>
#include "live_capture.h"
#include "HttpDetector.h"
using namespace std;


int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    // Instead of manual device selection, start capturing on all devices automatically:
    startLiveCaptureAllDevices();

    return 0;
}

