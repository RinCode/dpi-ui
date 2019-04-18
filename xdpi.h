#ifndef XDPI_H
#define XDPI_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <inttypes.h>
#include <getopt.h>
#include <stdio.h>
#include "string.h"
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ndpi_api.h"
#include "ndpi_util.h"

struct result{
    struct ndpi_flow_info *flow;
    struct result * next;
};

void initDetect(pcap_t *handle);
void handlePacket(const struct pcap_pkthdr *header, const u_char *packet,struct result *result);

#ifdef __cplusplus
}
#endif

#endif // DPI_H
