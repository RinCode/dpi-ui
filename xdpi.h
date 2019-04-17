#ifdef __cplusplus
extern "C"
{
#endif

#include <pcap.h>

void initDetect(pcap_t *handle);
void handlePacket(const struct pcap_pkthdr *header, const u_char *packet);

#ifdef __cplusplus
}
#endif
