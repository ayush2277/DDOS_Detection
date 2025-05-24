#include "UdpEntropyCusumDetector.h"
#include <cmath>
#include <algorithm>

UdpEntropyCusumDetector::UdpEntropyCusumDetector() {
    lastCalcTime = std::chrono::steady_clock::now();
    cusumValue = 0.0;
    baselineEntropySrc = 3.5;
    baselineEntropyDst = 3.5;
    thresholdEntropyChange = 0.5;
    cusumThreshold = 0.7;
    totalPacketsInWindow = 0;
    avgPacketCount = 0.0;
    stddevPacketCount = 0.0;
    attackDetected = false;
    alphaEWMA = 0.3;
}

bool UdpEntropyCusumDetector::update(const std::string& srcIP, int dstPort) {
    srcIPCount[srcIP]++;
    dstPortCount[dstPort]++;
    totalPacketsInWindow++;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastCalcTime);
    if (elapsed.count() < 2) return false;

    double entropySrc = calculateEntropy(srcIPCount);
    double entropyDst = calculateEntropy(dstPortCount);

   // std::cout << "Entropy (src): " << entropySrc << ", Entropy (dst): " << entropyDst
            //  << ", Packet count: " << totalPacketsInWindow << std::endl;

    updateDynamicThresholds(totalPacketsInWindow);
    applyCUSUM(entropySrc);

    bool volumeAttack = (totalPacketsInWindow > avgPacketCount + 2.5 * std::sqrt(stddevPacketCount));
    bool entropyAnomaly = (std::abs(entropySrc - baselineEntropySrc) > thresholdEntropyChange) ||
                           (std::abs(entropyDst - baselineEntropyDst) > thresholdEntropyChange);

    //std::cout << "Volume attack: " << volumeAttack << ", Entropy anomaly: " << entropyAnomaly << std::endl;

    bool justAlerted = false;
    if ((volumeAttack || entropyAnomaly) && !attackDetected) {
        // std::cout << "[ALERT] UDP flood detected! Entropy (src): " << entropySrc
        //           << ", Entropy (dst): " << entropyDst
        //           << ", Packet count: " << totalPacketsInWindow << std::endl;
        attackDetected = true;
        justAlerted = true;
    }
    if (!volumeAttack && !entropyAnomaly) attackDetected = false;

    lastCalcTime = now;
    return justAlerted;
}

template<typename T>
double UdpEntropyCusumDetector::calculateEntropy(const std::unordered_map<T, int>& countMap) {
    int total = 0;
    for (const auto& kv : countMap) total += kv.second;
    if (total == 0) return 0.0;

    double H = 0.0;
    for (const auto& kv : countMap) {
        double p = double(kv.second) / total;
        H -= p * log2(p);
    }
    return H;
}

template double UdpEntropyCusumDetector::calculateEntropy<std::string>(const std::unordered_map<std::string, int>&);
template double UdpEntropyCusumDetector::calculateEntropy<int>(const std::unordered_map<int, int>&);

void UdpEntropyCusumDetector::applyCUSUM(double entropy) {
    double dev = entropy - baselineEntropySrc;
    cusumValue = std::max(0.0, cusumValue + dev);
    if (cusumValue > cusumThreshold) {
        attackDetected = true;
        cusumValue = 0.0;
    }
}

void UdpEntropyCusumDetector::updateDynamicThresholds(int packets) {
    if (avgPacketCount == 0.0) {
        avgPacketCount = packets;
        stddevPacketCount = 0.0;
    } else {
        double d = packets - avgPacketCount;
        avgPacketCount = alphaEWMA * packets + (1 - alphaEWMA) * avgPacketCount;
        stddevPacketCount = alphaEWMA * (d * d) + (1 - alphaEWMA) * stddevPacketCount;
    }
}