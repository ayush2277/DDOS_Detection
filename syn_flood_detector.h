#ifndef SYN_FLOOD_DETECTOR_H
#define SYN_FLOOD_DETECTOR_H

#include <string>
#include <unordered_map>

using namespace std;

class SYNFloodDetector {
private:
    unordered_map<string, int> synCount;
    unordered_map<string, int> synAckCount;
    unordered_map<string, double> ewmaRatio;
    std::unordered_map<std::string, double> lastEWMA;

    // const double ALPHA = 0.125;           // Weight for the EWMA calculation
    // const double EWMA_THRESHOLD = 3.0;   // Threshold for EWMA to detect attack
    // const int SYN_THRESHOLD = 50;         // Threshold for SYN count to detect attack


public:
    void processPacket(const string& srcIP, const string& dstIP, bool synFlag, bool ackFlag);
    void checkForAttack(const std::string& srcIP);
};

#endif
