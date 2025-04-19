#ifndef SYN_FLOOD_DETECTOR_H
#define SYN_FLOOD_DETECTOR_H

#include <string>
#include <unordered_map>
#include <ctime>

class SYNFloodDetector {
private:
    std::unordered_map<std::string, int> synCount;
    std::unordered_map<std::string, int> synAckCount;
    std::unordered_map<std::string, double> ewmaRatio;
    std::unordered_map<std::string, double> lastEWMA;
    std::unordered_map<std::string, time_t> lastSeen;     // <-- 🆕 added
    std::unordered_map<std::string, bool> flaggedSources;
    std::unordered_map<std::string, time_t> lastAlerted; // <-- 🆕 added
public:
    void processPacket(const std::string& srcIP, const std::string& dstIP, bool synFlag, bool ackFlag);
    void checkForAttack(const std::string& srcIP, time_t now);  // <-- 🆕 updated signature
};

#endif
