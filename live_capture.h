#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H



#include <fstream>
extern std::ofstream outputFile;

void setupTCPConnection();
void startLiveCaptureAllDevices();

#endif
