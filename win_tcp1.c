#include <stdio.h>
#include <pcap.h>
#include <windows.h>

#define ETHER_HEADER 14
#define IP_HEADER 20
#define TCP_HEADER 20
/* 
==================
主函数
*************************
pcap_if  
		头文件：#include <pcap.h> （pcap_if_t等价于pcap_if）
  	struct pcap_if  
  	{
  		struct pcap_if *next;
  		char *name;
  		char *description;
  		struct pcap_addr* addresses;
  		bpf_u_int32 flags;  //bpf_u_int32等价于unsigned int
  	} 
*************************

*************************
int pcap_findalldev(pcap_if_t **alldevsp,char* errbuf)
	功能：获取设备列表，以供函数pcap_open_live()打开这些设备		
	返回值：-1（失败） 其它（成功）
*************************

*************************
pcap_t* pcap_open_live(
	
	  const char* device,   //要打开的网卡
	  int snaplen,          //捕捉的数据包的最大长度，单位为Byte
	  int promisc,          //是否为混杂模式，1为混杂模式
	  int to_ms,			//读取时的超时值，单位是毫秒，to_ms值会影响3个捕获函数(pcap_next、pcap_loop、pcap_dispatch)的行为
	  char* ebuf	
 )
*************************

*************************
pcap_t(网卡描述符)
*************************

*************************
int pcap_loop(
	  pcap_t *p,			 //已经打开的网卡 
	  int cnt,				 //在函数返回前应该捕捉多少个数据包（若为负值则表示应该一直工作直至错误发生）
	  pcap_handler callback, //回调函数的名称
	  u_char *user			 //一般为NULL
)
捕获数据包,不会响应pcap_open_live()函数设置的超时时间
*************************

*************************
pcap_pkthdr{ 
struct timeval ts;			 //ts：时间戳
bpf_u_int32 caplen;			 //caplen：真正实际捕获的包的长度 
bpf_u_int32 len;			 //len：数据包的长度
};
因为在某些情况下你不能保证捕获的包是完整的，例如一个包长1480，但是你捕获到1000的时候，可能因为某些原因就中止捕获了，所以caplen是记录实际捕获的包长，也就是1000，而len就是1480。 
*************************

*************************
头文件：#include <windows.h>
struct in_addr
{
    in_addr_t s_addr;
};
结构体in_addr 用来表示一个32位的IPv4地址，in_addr_t 一般为 32位的unsigned int，其字节顺序为网络顺序（network byte ordered)

打印的时候可以调用inet_ntoa()函数将其转换为char *类型
char *inet_ntoa (struct in_addr);
*************************
==================
*/
//ip头部
struct iphdr{
	   unsigned char     version_h_len;//版本号 和包头长度
	   unsigned char    tos;//服务类型
	   unsigned short   total_len;//包总长度
	   unsigned short   ident;//唯一标识符
	   unsigned short   frag_and_flages;//标志
	   unsigned char    ttl;//生存时间
	   unsigned char    proto;//传输协议
	   unsigned short   checksum;//校验和
	   unsigned int     souceIP;//源ip
	   unsigned int     destIP;//目标ip
};
//tcp头部
struct tcphdr{
	unsigned short sport;             //源端口
	unsigned short dport;             //目的端口
	unsigned int seq;                 //序列号
	unsigned int ack;                 //确认号
	unsigned short header_flags;	  //4 bits 首部长度，6 bits 保留位，6 bits 标志位
	unsigned short window;			  //窗口大小
	unsigned short sum;				  //校验和
	unsigned short urp;				  //紧急指针
};

//回调函数声明
void my_callback(
		u_char *argument,					  //参数argument是从函数pcap_loop()传递过来的
		const struct pcap_pkthdr *pkthdr,	  //参数pcap_pkthdr 表示捕获到的数据包基本信息,包括时间,长度等信息.
		const u_char *packet                  //packet_content表示的捕获到的数据包的内容
);

int main(void)
{
  //网卡描述符
  pcap_if_t *pcap_if = NULL;
  pcap_t* dev;
  //保存错误信息
  char error[1024];
  //1、开始查找设备
  int result = pcap_findalldevs(&pcap_if,error);
  if(-1 == result)
  {
 	return -1;
 	printf("finding devices is failed!!!\n");
  }
 //输出网卡名称
  printf("The name of selected network card is %s\n",(pcap_if->description));
 
 /*********************************************************************************/
  
  //2、打开网卡
  dev = pcap_open_live(pcap_if->name,1600,1,0,error);

  if(NULL == dev)
  {
	  printf("Opening the network card s is failed!!!\n");
	  return -1;
  }
  //3、过滤（先不写）

  //4、抓包
  pcap_loop(dev,-1,my_callback,NULL);
  pcap_close(dev);
  return 0;
}
void my_callback(u_char *argument, const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
	//开始解析和枪机（192.168.1.202）通信的数据包

	struct in_addr addr;		//放ip地址的结构体，本质就是unsigend int 
	struct iphdr *ipptr;		//ip头部
	struct tcphdr *tcpptr;		//tcp头部
	char *data;                 //data指向数据

/***************解析ip头部**************************/
	ipptr = (struct iphdr*)(packet+ETHER_HEADER); //以太网帧占14个字节
	/*解析数据包中的源目IP*/
	addr.s_addr = ipptr->destIP;
    //printf ("Destination IP: %s\n", inet_ntoa(addr));  //注意考虑电脑大小端问题
    addr.s_addr = ipptr->souceIP;
    //printf ("Source IP: %s\n", inet_ntoa(addr));
	
/***************解析tcp头部**************************/
	tcpptr = (struct tcphdr*)(packet+ETHER_HEADER+IP_HEADER); //以太网帧占14个字节，ip头部占20个字节
	//printf ("Destination Port: %u\n",ntohs(tcpptr->dport));
	//printf ("Source Port: %u\n", ntohs(tcpptr->sport));
	//ntohs()用来将网络字节序转成主机字节序  

/***************开始解析数据，看是否能拿到照片的所有分包，一定要在登录后开启此程序**************************/
	data = (char*)(packet+TCP_HEADER+IP_HEADER+ETHER_HEADER);
}
