#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
        
#define PCAP_SNAPSHOT 1024
#define PCAP_TIMEOUT 100
        
void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
int main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
        
	if(!(dev = pcap_lookupdev(errbuf)))
	{
		perror(errbuf);
		exit(1);
	}
        
	if((pd = pcap_open_live(dev, PCAP_SNAPSHOT, 1, PCAP_TIMEOUT, errbuf)) == NULL) 
	{
		perror(errbuf);
		exit(1);
	}
        
	if(pcap_loop(pd, -1, packet_view, 0) < 0) 
	{
		perror(pcap_geterr(pd));
		exit(1);
	}
        
	pcap_close(pd);
        return 0;
}

void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
{
	int i;
	
	//check TCP		 
	if(*(p+23) != 6)
		return;
	//chekc IP
	if(0x800 != ntohs((unsigned short*)p[12]))
		return;

	//<ethernet>
	p+=6;
	printf("Source MAC : ");
	for(i=0;i<6;i++)
	{
		printf("%.2X",*(p++));
		if(i<5)
			printf(":");
	}
	printf("\n");

	p-=12;
	printf("Destination MAC : ");
	for(i=0;i<6;i++)
        {
                printf("%.2X",*(p++));
                if(i<5)
                        printf(":");
        }
        printf("\n");

	p+=8;
	//</ethernet>

	//<ip>
	p+=12;

	printf("Source IP : ");
	for(i=0;i<4;i++)
        {
                printf("%d",*(p++));
                if(i<3)
                        printf(".");
        }
        printf("\n");

	printf("Destination IP : ");
	for(i=0;i<4;i++)
        {
                printf("%d",*(p++));
                if(i<3)
                        printf(".");
        }
        printf("\n");

//	p+=4;
	//</ip>

	//<tcp>
	printf("Source Port : ");
	printf("%d\n", ntohs(*((unsigned short*)p)));
	p+=2;
	printf("Destination Port : ");
	printf("%d\n", ntohs(*((unsigned short*)p)));
	//</tcp>
	printf("\n");
	return ;
}

