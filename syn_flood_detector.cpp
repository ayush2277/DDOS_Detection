#include "syn_flood_detector.h"
#include <iostream>
#include <cmath> // For absolute value calculation

using namespace std;

SYNFloodDetector synDetector;

// Define thresholds for high traffic environments
const double EWMA_THRESHOLD = 100.0;   // High threshold to avoid false positives in busy environments
const int SYN_THRESHOLD = 500;          // Higher threshold for SYN packets to accommodate legitimate traffic

// Define the smoothing factor for EWMA
const double ALPHA = 0.05;   // More gradual smoothing for realistic traffic fluctuations

// Max allowable rate of increase for EWMA ratio
const double MAX_EWMA_INCREASE = 5.0; // Allows small fluctuations but prevents sudden spikes from triggering

// Define the time window for SYN traffic analysis (in seconds, for example)
const int TRAFFIC_WINDOW = 60;  // A 60-second window for SYN traffic analysis

void SYNFloodDetector::processPacket(const string& srcIP, const string& dstIP, bool synFlag, bool ackFlag) {
    // Update SYN and SYN-ACK counts based on flags
    if (synFlag && !ackFlag) {
        synCount[srcIP]++;
    } else if (synFlag && ackFlag) {
        synAckCount[srcIP]++;
    }

    // Calculate the SYN/SYN-ACK ratio
    double ratio = 0.0;
    if (synAckCount[srcIP] > 0) {
        ratio = static_cast<double>(synCount[srcIP]) / synAckCount[srcIP];
    } else if (synCount[srcIP] > 10) {
        ratio = static_cast<double>(synCount[srcIP]);
    }

    // Update the Exponentially Weighted Moving Average (EWMA)
    if (ewmaRatio.find(srcIP) == ewmaRatio.end()) {
        ewmaRatio[srcIP] = ratio;
    } else {
        ewmaRatio[srcIP] = ALPHA * ratio + (1 - ALPHA) * ewmaRatio[srcIP];
    }

    // Check for abnormal increase in EWMA ratio
    if (abs(ewmaRatio[srcIP] - lastEWMA[srcIP]) > MAX_EWMA_INCREASE) {
        // Ignore the alert if the change is too rapid (indicating a burst, not a sustained attack)
        return;
    }

    // Store the current EWMA for comparison in the next cycle
    lastEWMA[srcIP] = ewmaRatio[srcIP];

    // Check if the SYN flood attack threshold is crossed
    checkForAttack(srcIP);
}

void SYNFloodDetector::checkForAttack(const string& srcIP) {
    // Detect potential SYN flood attack only if both thresholds are exceeded
    if (ewmaRatio[srcIP] > EWMA_THRESHOLD && synCount[srcIP] > SYN_THRESHOLD) {
        cout << "[ALERT] Possible SYN Flood detected from: " << srcIP
             << " | EWMA Ratio: " << ewmaRatio[srcIP]
             << " | Total SYNs: " << synCount[srcIP] << endl;
    }
}
