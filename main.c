#include <unistd.h>
#include <pcap.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet);
u_int16_t x = 0x4000;
int main(void)
{
      //1 找出第一网卡，确定要抓的网卡
   pcap_if_t *pcap_if;
    //  typedef struct pcap_if pcap_if_t;
   char Error[1024]; //保存错误信息
   int r= pcap_findalldevs(&pcap_if,Error);
   if(-1==r)
   {
      printf("wangkachazhaoshibai\n");
      return -1;
   }
   printf("The name of the first network card is %s\n",pcap_if[0].name);

        //2、打开这个网卡
pcap_t *dev = pcap_open_live(pcap_if[0].name,1600,1,0,Error); //网卡描述符
//
if(NULL==dev)
{
   printf("Opening the network card s is failed!!!\n ");
   return -1;
}
//3、设置过滤选项
//4、抓包
struct pcap_pkthdr hdr ; //所抓到的包的信息，长度等
/*const u_char *packet=pcap_next(dev,&hdr); //pcaket所指向的内容不能改
if(NULL==packet)
{
   printf("capturing packages is failed!!!\n");
   pcap_close(dev);
   return -1;
}
printf("包的长度是%d\n",hdr.caplen);
printf("包的长度是%d\n",hdr.len);
printf("------------------------------\n");
printf("%c",packet[1]);*/
int a = pcap_loop(dev,-1,my_callback,NULL);
pcap_close(dev);

        return 0;
}
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet)
{
    struct in_addr addr;
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;//太次片，，ip，tcp数据结构
    char *data;

    pcap_t *descr = (pcap_t*)userless;//捕获网络数据包的数据包捕获描述字
    //const u_char *packet;
    struct pcap_pkthdr hdr = *pkthdr;//(libpcap 自定义数据包头部)，
    struct ether_header *eptr;//以太网字头
    u_char *ptr;
    int i;

    if (packet == NULL)//packet里面有内容，可以证明上面的猜想，
    {
        printf ("Didn't grab packet!/n");
        exit (1);
    }
    printf ("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    printf ("Grabbed packet of length %d\n", hdr.len);
    printf ("Received at : %s\n", ctime((const time_t*)&hdr.ts.tv_sec));
    printf ("Ethernet address length is %d\n",14);
eptr=(struct ether_header*)packet;
 if(ntohs(eptr->ether_type)==ETHERTYPE_IP)
    {
        //printf("IP数据包\n");
        printf ("Ethernet type hex:%x dec:%d is an IP packet/n",
                    ntohs(eptr->ether_type), ntohs(eptr->ether_type));
}
 else
    {
           if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
           {
                printf("ARP数据包\n");

           }
           else
           {
                printf("不是IP也不是arp数据包\n");
                //exit( -1);
           }
    }
ptr = eptr->ether_dhost;
i = ETHER_ADDR_LEN;
printf("i=%d\n",i);
printf("Destination Address:");
do
{
 printf("%s%x",(i==ETHER_ADDR_LEN)?"":":",*ptr++);
}while(--i>0);
printf("\n");

ptr=eptr->ether_shost;
i=ETHER_ADDR_LEN;
printf("Source Address:");
 do
   {
        printf ("%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
  }while(--i>0);
 printf ("\n");

 printf ("Now decoding the IP packet.\n");

ipptr=(struct iphdr*) (packet+sizeof(struct ether_header)); //get ip header
 printf ("the IP packets total_length is :%d\n", ipptr->tot_len);
printf ("the IP protocol is %d\n", ipptr->protocol); //6shi tcp
printf("******%lld****\n",ipptr->id);
printf("#####%d#####",(ipptr->frag_off)&x);
addr.s_addr = ipptr->daddr;
  printf ("Destination IP: %s\n", inet_ntoa(addr));
    addr.s_addr = ipptr->saddr;
    printf ("Source IP: %s\n", inet_ntoa(addr));

printf ("Now decoding the TCP packet.\n");

 tcpptr = (struct tcphdr*)(packet+sizeof(struct ether_header) +sizeof(struct iphdr));//得到tcp包头
// if(tcpptr!=NULL) printf("hahhaha");
 printf ("Destination port : %d\n", tcpptr->dest);
   printf ("Source port : %d\n", tcpptr->source);
    printf ("the seq of packet is %lld\n",tcpptr->seq);

//data = (char*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr)
//                                    +sizeof(struct tcphdr));//得到数据包里内容
//printf("the content of packets is \n%s\n",data);
