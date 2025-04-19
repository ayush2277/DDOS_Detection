#include <iostream>
#include "live_capture.h"

using namespace std;

int main() {
    cout << "Starting DDoS Detection Framework on all interfaces..." << endl;
    startLiveCaptureAllDevices();  // This starts multiple threads
    return 0;
}
