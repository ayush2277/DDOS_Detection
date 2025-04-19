#include "syn_flood_detector.h"
#include <iostream>
#include <cmath>      // For absolute value calculation
#include <ctime>      // For time management

using namespace std;

SYNFloodDetector synDetector;

// Define thresholds for high traffic environments
const double EWMA_THRESHOLD = 500;   // High threshold to avoid false positives in busy environments
const int SYN_THRESHOLD = 1000;         // Higher threshold for SYN packets to accommodate legitimate traffic

// Define the smoothing factor for EWMA
const double ALPHA = 0.1;             // More gradual smoothing for realistic traffic fluctuations

// Max allowable rate of increase for EWMA ratio
const double MAX_EWMA_INCREASE = 5.0;  // Allows small fluctuations but prevents sudden spikes from triggering

// Define the time window for SYN traffic analysis (in seconds, for example)
const int TRAFFIC_WINDOW = 60;         // 60-second window for SYN traffic analysis

// Cooldown period to prevent repeated alerts for same IP (in seconds)
const int ALERT_COOLDOWN = 120;        // 2 minutes

void SYNFloodDetector::processPacket(const string& srcIP, const string& dstIP, bool synFlag, bool ackFlag) {
    time_t now = time(nullptr);

    // Reset counters if last packet was long ago (Reset Counters Over Time)
    if (lastSeen.find(srcIP) != lastSeen.end()) {
        if (now - lastSeen[srcIP] > TRAFFIC_WINDOW) {
            synCount[srcIP] = 0;
            synAckCount[srcIP] = 0;
            ewmaRatio[srcIP] = 0.0;
            lastEWMA[srcIP] = 0.0;
        }
    }
    lastSeen[srcIP] = now;

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
        cout << "[WARN] Sudden EWMA spike for " << srcIP 
             << " | Old: " << lastEWMA[srcIP] 
             << " | New: " << ewmaRatio[srcIP] << endl;
    }
    

    // Store the current EWMA for comparison in the next cycle
    lastEWMA[srcIP] = ewmaRatio[srcIP];

    // Check if the SYN flood attack threshold is crossed
    checkForAttack(srcIP, now);
}

void SYNFloodDetector::checkForAttack(const string& srcIP, time_t now) {
    // Detect potential SYN flood attack only if both thresholds are exceeded
    if (ewmaRatio[srcIP] > EWMA_THRESHOLD && synCount[srcIP] > SYN_THRESHOLD) {

        // Ignore if recently alerted (Ignore Already-Flagged Sources logic)
        if (lastAlerted.find(srcIP) != lastAlerted.end()) {
            if (now - lastAlerted[srcIP] < ALERT_COOLDOWN) {
                return;  // Skip duplicate alert
            }
        }

        lastAlerted[srcIP] = now;  // Update last alert time

        cout << "[ALERT] Possible SYN Flood detected from: " << srcIP
             << " | EWMA Ratio: " << ewmaRatio[srcIP]
             << " | Total SYNs: " << synCount[srcIP] << endl;
    }
}
