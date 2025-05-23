#ifndef HTTP_DETECTOR_H
#define HTTP_DETECTOR_H
#include <string>
#include <unordered_map>

class HttpDetector {
public:
    struct CusumData {
        double mean = 0;
        double cusum = 0;
        int count = 0;
    };

    void processPacket(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort, int size);

     HttpDetector();


    HttpDetector(const std::string& filename);
    void run();

    static std::unordered_map<std::string, CusumData> ipCusum;
    static std::unordered_map<std::string, int> ipFrequency;
    static int totalPacketWindow;

private:
    std::string filename;
    void monitorTraffic();
    bool parseLine(const std::string& line, std::string& timestamp, std::string& srcIP, std::string& appProtocol);
    double calculateEntropy();
    void handleCusum(const std::string& srcIP);
    void handleEntropy(const std::string& srcIP);
    void resetWindow();
   
};

#endif