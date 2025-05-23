#pragma once
#include <unordered_map>
#include <string>
#include <iostream>
#include <chrono>

class UdpEntropyCusumDetector {
private:
    std::unordered_map<std::string, int> srcIPCount;
    std::unordered_map<int, int> dstPortCount;
    std::chrono::steady_clock::time_point lastCalcTime;
    double cusumValue;
    double baselineEntropySrc;
    double baselineEntropyDst;
    double thresholdEntropyChange;
    double cusumThreshold;
    int totalPacketsInWindow;

    double avgPacketCount;
    double stddevPacketCount;
    bool attackDetected;
    double alphaEWMA;

public:
    UdpEntropyCusumDetector();

    bool update(const std::string& srcIP, int dstPort);

private:
    template<typename T>
    double calculateEntropy(const std::unordered_map<T, int>& countMap);

    void applyCUSUM(double entropy);
    void updateDynamicThresholds(int packets);
};