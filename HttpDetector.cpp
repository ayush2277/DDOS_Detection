#include "HttpDetector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
#include <thread>
#include <windows.h>

using namespace std;

unordered_map<string, HttpDetector::CusumData> HttpDetector::ipCusum;
unordered_map<string, int> HttpDetector::ipFrequency;
int HttpDetector::totalPacketWindow = 0;

const double thresholdCusum = 30.0;
const double slackK = 5.0;
const double entropyThreshold = 1.5;

HttpDetector::HttpDetector(const string& filename) : filename(filename) {}

void HttpDetector::run() {

    cout << "🚨 HTTP/HTTPS Flood Detector Running (CUSUM + Entropy)..." << endl;
    monitorTraffic();
}



bool HttpDetector::parseLine(const string& line, string& timestamp, string& srcIP, string& appProtocol) {
    stringstream ss(line);
    string field;
    int col = 0;
    while (getline(ss, field, ',')) {
        if (col == 0) timestamp = field;
        else if (col == 1) srcIP = field;
        else if (col == 7) {
            appProtocol = field;
            return true;
        }
        ++col;
    }
    return false;
}

double HttpDetector::calculateEntropy() {
    double entropy = 0.0;
    for (auto& pair : ipFrequency) {
        double p = static_cast<double>(pair.second) / totalPacketWindow;
        if (p > 0) entropy -= p * log2(p);
    }
    return entropy;
}

void HttpDetector::handleCusum(const string& srcIP) {
    auto& data = ipCusum[srcIP];
    data.count++;
    double deviation = data.count - data.mean - slackK;
    data.cusum += deviation;

    if (data.count % 10 == 0) {
        data.mean = (data.mean * 0.8) + (data.count * 0.2);
        data.count = 0;
    }

    if (data.cusum > thresholdCusum) {
        cout << "⚠ [CUSUM] Possible Flood from " << srcIP << " [CUSUM: " << data.cusum << "]" << endl;
        data.cusum = 0;
    }
}

void HttpDetector::handleEntropy(const string& srcIP) {
    ipFrequency[srcIP]++;
    totalPacketWindow++;

    if (totalPacketWindow % 50 == 0) {
        double entropy = calculateEntropy();
        if (entropy < entropyThreshold) {
            cout << "⚠ [Entropy] Low entropy detected (" << entropy << ") → Possible coordinated attack." << endl;
        }
        resetWindow();
    }
}

void HttpDetector::processPacket(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort, int size) {
    handleCusum(srcIP);
    handleEntropy(srcIP);
}

void HttpDetector::resetWindow() {
    ipFrequency.clear();
    totalPacketWindow = 0;
}

HttpDetector::HttpDetector() {
    // You can leave this empty or add any default initialization if needed
}

void HttpDetector::monitorTraffic() {
    ifstream file;
    streampos lastPos = 0;
    string line, timestamp, srcIP, appProtocol;

    while (true) {
        file.open(filename);
        if (!file.is_open()) {
            cerr << "Failed to open file." << endl;
            Sleep(1000);
            continue;
        }

        file.seekg(lastPos);

        while (getline(file, line)) {
            if (!parseLine(line, timestamp, srcIP, appProtocol)) continue;
            if (appProtocol != "HTTP" && appProtocol != "HTTPS") continue;

            handleCusum(srcIP);
            handleEntropy(srcIP);
        }

        lastPos = file.tellg();
        file.close();
        Sleep(1000);
    }
}
