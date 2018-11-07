#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <memory.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h> // sockaddr_ll
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <pthread.h>

#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/msg.h>
#include<string.h>
#include<unistd.h>
#include <errno.h>

//#include <iostream> // The packet length

#define PCKT_LEN 100 // UDP的伪头部
struct UDP_PSD_Header {
  unsigned long src;
  unsigned long des;
  unsigned char mbz;
  unsigned char ptcl;
  unsigned int len;
}; 

void printbuf(unsigned char* buf, int len);
void printip(unsigned char* buf, int len);
#if 0
#define ETH_ALEN 6  //定义了以太网接口的MAC地址的长度为6个字节
#define ETH_HLEN 14  //定义了以太网帧的头长度为14个字节
#define ETH_ZLEN 60  //定义了以太网帧的最小长度为 ETH_ZLEN + ETH_FCS_LEN = 64个字节
#define ETH_DATA_LEN 1500  //定义了以太网帧的最大负载为1500个字节
#define ETH_FRAME_LEN 1514  //定义了以太网正的最大长度为ETH_DATA_LEN + ETH_FCS_LEN = 1518个字节
#define ETH_FCS_LEN 4   //定义了以太网帧的CRC值占4个字节
struct ethhdr
{
  unsigned char h_dest[ETH_ALEN]; //目的MAC地址
  unsigned char h_source[ETH_ALEN]; //源MAC地址
  __u16 h_proto ; //网络层所使用的协议类型
}__attribute__((packed))  //用于告诉编译器不要对这个结构体中的缝隙部分进行填充操作；

#define ETH_P_IP 0x0800 //IP协议
#define ETH_P_ARP 0x0806  //地址解析协议(Address Resolution Protocol)
#define ETH_P_RARP 0x8035  //返向地址解析协议(Reverse Address Resolution Protocol)
#define ETH_P_IPV6 0x86DD  //IPV6协议
#define ETH_P_ALL  0x0003          /* Every packet (be careful!!!) */

#define	AF_PACKET	17	/* Packet family.  */
#define	PF_PACKET AF_PACKET

struct sockaddr_ll {
  unsigned short sll_family; /* Always AF_PACKET */
  unsigned short sll_protocol; /* Physical-layer protocol */
  int sll_ifindex; /* Interface number */
  unsigned short sll_hatype; /* ARP hardware type */
  unsigned char sll_pkttype; /* Packet type */
  unsigned char sll_halen; /* Length of address */
  unsigned char sll_addr[8]; /* Physical-layer address */
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8 ihl:4,
  version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
  __u8 version:4,
  ihl:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
  __u8 tos;
  __be16 tot_len;
  __be16 id;
  __be16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __be16 check;
  __be32 saddr;
  __be32 daddr;
};

|----|----|------|--|-------------------|----------
|ver |ihl | -tos | -|    tot_len        |
|----|----|------|--|-------------------|
|       id          |   frag_off       -|
|---------|---------|-------------------|
|   ttl   |protocol |    check          | 20 Bytes
|---------|---------|-------------------|
|                saddr                  |
|---------------------------------------|
|                daddr                  |
|---------------------------------------|----------
|                                       |
|                options                | 40 Bytes
|                                       |
|---------------------------------------|----------
#endif

// 计算校验和
unsigned short csum(unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)	{
    sum += *buf++;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

//unsigned char remoteMac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00}; // fireboard
//unsigned char localMac[ETH_ALEN] = {0x00, 0x16, 0xd3, 0x3b, 0x35, 0x32}; // rico local linux pc

unsigned char remoteMac[ETH_ALEN] = {0xee, 0xff, 0xff, 0xff, 0xff, 0xff}; // alicloud gateway pc
unsigned char localMac[ETH_ALEN] = {0x00, 0x16, 0x3e, 0x0a, 0x6b, 0xe3}; // alicloud pc

//unsigned char remoteMac[ETH_ALEN] = {0xfa, 0x16, 0x3e, 0x45, 0xbb, 0x7e}; // hwcloud gateway pc
//unsigned char localMac[ETH_ALEN] = {0xfa, 0x16, 0x3e, 0x26, 0x4e, 0xb4}; // hwcloud pc

//unsigned long srcIpAddr = 0xa90911ac; // aliyun private ip:172.17.9.169
unsigned long srcIpAddr = 0x820010ac; // hwyun private ip:172.16.0.130

unsigned long ali_inner_IpAddr = 0xa90911ac;// aliyun private ip:172.17.9.169
unsigned long last_peer_IpAddr = 0;
unsigned long allowed_peer_IpAddr = 0;
unsigned long last_ue_IpAddr = 0;
unsigned char last_ue_head[50] = {0};
unsigned short last_ue_port = 0;

int msgid = 0;
typedef struct msgbufSelf{
	long type;
	unsigned short direct;  //0: ali->server   1:ali->ue
	unsigned short len;
	unsigned char data[2000];
}msgbufSelf;


int type =0;
struct sd_all
 {
 int sd_raw;
 int sd_icmp;
 int sd_forward;
 int sd_ip;
 };
//unsigned long dstIpAddr = 0x6a8e7372; // hwyun public ip:114.115.142.106
unsigned long dstIpAddr = 0x3dc55f2f; // aliyun public ip:47.95.197.61

#define Test_Data_Len 60




int sendpacket(int fd, unsigned long srcIp, unsigned long dstIp) {
  unsigned char buf[Test_Data_Len] = {0};

  // mac head
  struct ethhdr *macHd = (struct ethhdr *)buf;
  memcpy(macHd->h_dest, remoteMac, ETH_ALEN);
  memcpy(macHd->h_source, localMac, ETH_ALEN);
  macHd->h_proto = htons(ETH_P_IP);

  // ip head
  struct iphdr *ip = (struct iphdr *)(buf + ETH_HLEN);
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  // 服务类型
  // sizeof(phhdr) + data
  ip->tot_len = htons(Test_Data_Len - ETH_HLEN);
  ip->id = htons(1000);
  ip->frag_off = 0;
  ip->ttl = 255; // hops生存周期
  ip->protocol = 253; // nanrui packet
  //ip->protocol = 17; // UDP
  ip->check = 0;
  ip->saddr = srcIp;
  ip->daddr = dstIp;
  ip->check = csum((unsigned short *)ip, sizeof(struct iphdr) / 2);

  // udp head
  /*struct udphdr *udp = (struct udphdr *)(buf + ETH_HLEN + sizeof(struct iphdr));
  udp->source = htons(6000);
  udp->dest = htons(10000);
  udp->len = htons(Test_Data_Len - ETH_HLEN - sizeof(struct iphdr)); // 长度udp head + payload
  udp->check = csum((unsigned short *)udp, (Test_Data_Len - ETH_HLEN - sizeof(struct iphdr)) / 2);*/

  //memcpy(eh->h_dest, (void*)&dest_mac, ETH_ALEN);
  //memcpy(eh->h_source, (void*)&host.mac, ETH_ALEN);
  //eh->h_proto = htons(pro);
  struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(socket_address));
  //socket_address.sll_ifindex = if_nametoindex("ens2"); // rico local pc
  socket_address.sll_ifindex = if_nametoindex("eth0");
  printf("sendpacket eth0 index is %u\r\n", socket_address.sll_ifindex);
  socket_address.sll_halen = ETH_ALEN;
  memcpy((void*)socket_address.sll_addr,(void *)&macHd->h_dest[0], ETH_ALEN);
  int count;
  for (count = 1; count <= 2000000; count++) {
    if (sendto(fd, buf, Test_Data_Len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)	{
      perror("sendto() error");
      return -1;
    } else {
      printf("Count #%u - sendto() is OK.\n", count);
      sleep(10);
    }
  }

  return 0;
}


int forwardPacket(int fd,unsigned char* data, int len) 
{
  unsigned char buf[2048] = {0};

  // mac head
  //struct ethhdr *macHd = (struct ethhdr *)buf;
  //memcpy(macHd->h_dest, remoteMac, ETH_ALEN);
  //memcpy(macHd->h_source, localMac, ETH_ALEN);
  //macHd->h_proto = htons(ETH_P_IP);

  memcpy(buf, data, len);

  // ip head
  struct iphdr *ip = (struct iphdr *)(buf );
  ip->saddr = ali_inner_IpAddr;
  ip->check = csum((unsigned short *)ip, sizeof(struct iphdr) / 2);
  last_peer_IpAddr = ip->daddr;
  


  struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(socket_address));
  //socket_address.sll_ifindex = if_nametoindex("ens2"); // rico local pc
  socket_address.sll_ifindex = if_nametoindex("eth0");
  //printf("sendpacket eth0 index is %u, %d, %d\r\n", socket_address.sll_ifindex, ip->tot_len,ntohs(ip->tot_len) , ETH_HLEN);
  socket_address.sll_halen = ETH_ALEN;
  //memcpy((void*)socket_address.sll_addr,(void *)&macHd->h_dest[0], ETH_ALEN);
  int count;
    if (sendto(fd, buf,  ntohs(ip->tot_len), 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)	{
      perror("forwardPacket error\n");
      return -1;
    } else {
      printf("forwardPacket OK.\n");
      sleep(10);
    }
  

  return 0;
}

int forwardPacketBack(int fd,unsigned char* data, int len) 
{
  unsigned char buf[2048] = {0};

  memcpy(buf, last_ue_head, sizeof(struct iphdr)+sizeof(struct udphdr));
  memcpy(buf+sizeof(struct iphdr)+sizeof(struct udphdr),data, len);

  struct iphdr *ip = (struct iphdr *)(buf);
  struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + sizeof(struct iphdr));
  ip->saddr = ali_inner_IpAddr;
  udp->source = htons(7000);
  ip->daddr = last_ue_IpAddr;
  udp->dest = last_ue_port;

  ip->tos = 0;
  ip->tot_len = ((sizeof(struct iphdr) + sizeof(struct udphdr) +len));
  ip->check = csum((unsigned short *)ip, sizeof(struct iphdr) / 2);
  udp->len = htons(sizeof(struct udphdr) +len); // 长度
  udp->check = csum((unsigned short *)udp, (sizeof(udphdr) + len + 1) / 2);

  struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(socket_address));
  socket_address.sll_ifindex = if_nametoindex("eth0");
  socket_address.sll_halen = ETH_ALEN;
    if (sendto(fd, buf,  len+sizeof(struct iphdr)+sizeof(struct udphdr), 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)	{
      perror("forwardPacketBack error\n");
      return -1;
    } else {
      printf("forwardPacketBack OK.\n");
      sleep(10);
    }
  

  return 0;
}

int forwardPacketBack_udp(int fd,unsigned char* data, int len) 
{

  unsigned char temp[] = {
    0x41, 0x41, 0x41, 0x41
  };



struct sockaddr_in dest_addr;
memset(&dest_addr, 0, sizeof(dest_addr));
dest_addr.sin_family = AF_INET;
dest_addr.sin_addr.s_addr = last_ue_IpAddr;
dest_addr.sin_port = last_ue_port;
ssize_t ret = sendto(fd, data, len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
if (ret < 0)	{
  perror("forwardPacketBack error\n");
  return -1;
} else {
  printf("forwardPacketBack OK.\n");
  //sleep(10);
}

}
int sendudp(int sd, unsigned long srcIp, unsigned short srcPort, unsigned long dstIp, unsigned short dstPort) {
  char buffer[PCKT_LEN]; // 查询www.chongfer.cn的DNS报文
  unsigned char DNS[] = {
    0xd8, 0xcb, 0x01, 0x00, 0x00, 0x01, 0x00 ,0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x08, 0x63, 0x68, 0x6f, 0x6e, 0x67, 0x66, 0x65,
    0x72, 0x02, 0x63, 0x6e, 0x00, 0x00, 0x01, 0x00,
    0x01
  };
  struct iphdr *ip = (struct iphdr *)buffer;
  struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct iphdr));
  // Source and destination addresses: IP and port
  struct sockaddr_in sin, din;
  // 缓存清零
  memset(buffer, 0, PCKT_LEN);

  // The source is redundant, may be used later if needed
  // The address family
  sin.sin_family = AF_INET;
  din.sin_family = AF_INET;
  // Port numbers
  sin.sin_port = srcPort;
  din.sin_port = dstPort;
  // IP addresses
  sin.sin_addr.s_addr = srcIp;
  din.sin_addr.s_addr = dstIp;
  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  ip->ihl = 5;
  ip->version = 4;
  // 报头长度,4*32=128bit=16B
  ip->tos = 0;
  // 服务类型
  ip->tot_len = ((sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS)));
  ip->id = htons(1000);
  ip->ttl = 255; // hops生存周期
  ip->protocol = 253; // nanrui packet
  //ip->protocol = 17; // 17:UDP
  ip->check = 0; // Source IP address, can use spoofed address here!!!
  ip->saddr = srcIp;
  // The destination IP address
  ip->daddr = dstIp;
  // Fabricate the UDP header. Source port number, redundant
  udp->source = srcPort; // 源端口
  // Destination port number
  udp->dest = dstPort; // 目的端口
  udp->len = htons(sizeof(struct udphdr) + sizeof(DNS)); // 长度
  // forUDPCheckSum用来计算UDP报文的校验和用
  // UDP校验和需要计算伪头部,UDP头部和数据部分
  char *forUDPCheckSum = new char[sizeof(UDP_PSD_Header) + sizeof(udphdr) + sizeof(DNS) + 1];
  memset(forUDPCheckSum, 0, sizeof(UDP_PSD_Header) + sizeof(udphdr) + sizeof(DNS) + 1);
  UDP_PSD_Header *udp_psd_Header = (UDP_PSD_Header *)forUDPCheckSum;
  udp_psd_Header->src = srcIp;
  udp_psd_Header->des = dstIp;
  udp_psd_Header->mbz = 0;
  udp_psd_Header->ptcl = 17;
  udp_psd_Header->len = htons(sizeof(udphdr) + sizeof(DNS));
  memcpy(forUDPCheckSum + sizeof(UDP_PSD_Header), udp, sizeof(udphdr));
  memcpy(forUDPCheckSum + sizeof(UDP_PSD_Header) + sizeof(udphdr), DNS, sizeof(DNS));
  //ip->check = csum((unsigned short *)ip, sizeof(iphdr) / 2); // 可以不用算
  // 计算UDP的校验和，因为报文长度可能为单数，所以计算的时候要补0
  udp->check = csum((unsigned short *)forUDPCheckSum, (sizeof(udphdr) + sizeof(UDP_PSD_Header) + sizeof(DNS) + 1) / 2);
  // setuid(getpid()); // 如果不是root用户，需要获取权限
  // Send loop, send for every 2 second for 2000000 count
  printf("Trying...\r\n");
  printf("Using raw socket and UDP protocol\r\n");
  printf("Using Source IP: 0x%x port: %u, Target IP: 0x%x port: %u.\r\n", srcIp, srcPort, dstIp, dstPort);
  printf("Ip length:%u\r\n", ip->tot_len);
  // 将DNS报文拷贝进缓存区
  memcpy(buffer + sizeof(iphdr) + sizeof(udphdr), DNS, sizeof(DNS));
  int count;
  for (count = 1; count <= 2000000; count++) {
    if (sendto(sd, buffer, ip->tot_len, 0, (struct sockaddr *)&din, sizeof(din)) < 0)	{
      perror("sendto() error");
      return -1;
    } else {
      printf("Count #%u - sendto() is OK.\n", count);
      sleep(2);
    }
  }

  return 0;
}

bool isRun = false;
void *receivePacket(void *arg) {
  int sd = *(int *)arg;
  int rcvLen = 0;
  printf("receivePacket sd is %d\n", sd);

  unsigned char buffer[2048] = {0};
  struct sockaddr_ll socket_address;
  int addrLen = 0;
  while (isRun) {
    rcvLen = recvfrom(sd, buffer, 2048, 0, (struct sockaddr *)&socket_address, (socklen_t *)&addrLen);
    if (rcvLen > 0) {

        struct iphdr *ip = (struct iphdr *)(buffer);
	 struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + sizeof(struct iphdr));
	 printf("ip=%ld,%ld",ip->daddr, ali_inner_IpAddr);
	 printbuf((unsigned char *)&(ip->daddr), 4);
	 printf("\r\nport=%d,%d",udp->dest,htons(7000));
	 printbuf((unsigned char *)&(udp->dest), 2);
	 printf("\r\n");

        if (ip->daddr == ali_inner_IpAddr && udp->dest==htons(7000)) {
		memcpy(last_ue_head, buffer, sizeof(struct iphdr)+ sizeof(struct udphdr));
		last_ue_IpAddr = ip->saddr;
              last_ue_port = udp->source;
			 	
		unsigned char *pPayLoad = (unsigned char *)udp + sizeof(struct udphdr);
		unsigned short payLoadLen = ntohs(ip->tot_len) - sizeof(struct iphdr)- sizeof(struct udphdr);          
		printf("receive len %u:", payLoadLen);
		printbuf((unsigned char *)pPayLoad, payLoadLen);
		printf("\r\n");
		forwardPacket(sd, pPayLoad,payLoadLen);
	}
    }
  }

  return NULL;
}
unsigned char rcvbuffer[4096] = {0};
unsigned char *pData=rcvbuffer;
short tlen=0;
bool long_package_mode=false;
void *receiveAllPacket(void *arg) {
  struct sd_all* sdall = (sd_all *)arg;
  int sd_raw=sdall->sd_raw;
  int sd_icmp = sdall->sd_icmp; 
  int sd_forward = sdall->sd_forward;
    int sd_ip = sdall->sd_ip;
  
  int rcvLen = 0;
  //printf("receivePacket sd is %d\n", sd);

  unsigned char buffer[4096] = {0};
  struct sockaddr_ll socket_address;
  int addrLen = 0;
  while (isRun) {
    rcvLen = recvfrom(sd_ip, buffer, 4096, 0, (struct sockaddr *)&socket_address, (socklen_t *)&addrLen);
    if (rcvLen > 0) {

		
		struct ethhdr *macHd = (struct ethhdr *)buffer;
		// ip head
		struct iphdr *ip = (struct iphdr *)(buffer + ETH_HLEN);
		struct udphdr *udp =NULL;

		if(ip->saddr == last_peer_IpAddr || ip->saddr == allowed_peer_IpAddr) //baidu->ali
		{
			int len =0;
			len = ntohs(ip->tot_len);

			printf("receiveICMP:receive len %u:", len);
			printbuf((unsigned char *)ip, len);
			printf("\r\n");

			forwardPacketBack_udp(sd_forward, (unsigned char *)ip, len); //ali->ue
			/*
			msgbufSelf buf;
			buf.type=1;
			buf.direct=1;
			buf.len=len;
			memcpy(buf.data, (unsigned char *)ip, len);
			if(msgsnd(msgid,&buf,len+4,0) == -1){
				perror("msgsnd");
			}		
			*/
			printf("send ok\r\n");
			continue;
		}

	if(ip->protocol = 17)   //ue->ali
	{
		udp = (struct udphdr *)((unsigned char *)ip + sizeof(struct iphdr));
		if (udp->dest==htons(7000)) {
			printf("src ip:");
			printip((unsigned char *)&(ip->saddr), 4);
			printf(", dst ip:");
			printip((unsigned char *)&(ip->daddr), 4);
			printf("\r\n");	 
			printf("\r\nsrc port=%d, dst port=%d\r\n",ntohs(udp->source), ntohs(udp->dest));			
			memcpy(last_ue_head, buffer, sizeof(struct iphdr)+ sizeof(struct udphdr));
			last_ue_IpAddr = ip->saddr;
			last_ue_port = udp->source;
				
			unsigned char *pPayLoad = (unsigned char *)udp + sizeof(struct udphdr);
			unsigned short payLoadLen = ntohs(ip->tot_len) - sizeof(struct iphdr)- sizeof(struct udphdr);    

/*

			if(!long_package_mode){pData = rcvbuffer;tlen=0;}
			
			memcpy(pData, pPayLoad,payLoadLen);
			tlen +=payLoadLen;
			
			if(!long_package_mode&&payLoadLen==512)
			{
				long_package_mode=true;
			}		
			else if(long_package_mode&&payLoadLen<512)
			{
				long_package_mode=false;
			}				

			if(payLoadLen==512)pData += 512;
			else pData += payLoadLen;
			*/
				printf("receive len %u:", payLoadLen);
				printbuf((unsigned char *)pPayLoad, payLoadLen);
				printf("\r\n");
				msgbufSelf buf;
				buf.type=1;
				buf.direct=type;
				buf.len=payLoadLen;
				memcpy(buf.data, pPayLoad, payLoadLen);
				if(msgsnd(msgid,&buf,payLoadLen+4,0) == -1){
					perror("msgsnd");
				}

		}
	}

    }
  }

  return NULL;
}

int sendcount=0;
void *sendAllPacket(void *arg) {
	struct sd_all* sdall = (sd_all *)arg;
	int sd_raw=sdall->sd_raw;
	int sd_icmp = sdall->sd_icmp; 
	int sd_forward = sdall->sd_forward;
	int sd_ip = sdall->sd_ip;
	int ret;
	unsigned char buffer[4096] = {0};

	while (isRun) 
	{
		msgbufSelf buf;

		if(msgrcv(msgid,&buf,sizeof(buf)-4,1,0)==-1){
			perror("msgrcv");
			//sleep(1);
			continue;
		}
		printf("sendcount=%d, direct=%d, len=%d, sizeof(buf)=%d\r\n", ++sendcount, buf.direct, buf.len, sizeof(buf));
		if(buf.direct==0)
		{
			forwardPacket(sd_raw, buf.data,buf.len);   //ali->baidu
		}
		else if(buf.direct ==1)
		{
		       //printf("type=1, reply directly.\r\n");
		       forwardPacketBack_udp(sd_forward, buf.data,buf.len); //ali->ue
		       /*
		       unsigned char *pData=buf.data;
			short len=0;
			short tlen=buf.len;
			while(tlen>0)
			{
				if(tlen>=512)len=512;
 				else len=tlen;

				forwardPacketBack_udp(sd_forward, pData, len); //ali->ue
				tlen -= len;
				pData+=len;
			}
			*/
		}
	}

	return NULL;
}
void *receiveICMP(void *arg) {
  struct sd_all* sdall = (sd_all *)arg;
  int sd_raw=sdall->sd_raw;
  int sd_icmp = sdall->sd_icmp; 
  int sd_forward = sdall->sd_forward;
  int rcvLen = 0;
  //printf("receivePacket sd is udp=%d,icmp=%d\n", sd_udp,sd_icmp);

  unsigned char buffer[2048] = {0};
  struct sockaddr_ll socket_address;
  int addrLen = 0;
  while (isRun) {
    rcvLen = recvfrom(sd_icmp, buffer, 2048, 0, (struct sockaddr *)&socket_address, (socklen_t *)&addrLen);
    if (rcvLen > 0) {

        struct iphdr *ip = (struct iphdr *)(buffer);
	 printf("receiveICMP:ip=%ld,%ld",ip->saddr, ali_inner_IpAddr);
	 printbuf((unsigned char *)&(ip->saddr), 4);
	 printf("\r\n");

        if(ip->saddr == last_peer_IpAddr) 
	{
		//unsigned char *pPayLoad = (unsigned char *)ip + sizeof(struct iphdr);
		//unsigned short payLoadLen = ntohs(ip->tot_len) - sizeof(struct iphdr);          
		int len =0;
		len = ntohs(ip->tot_len);

		  unsigned char temp[] = {
		    0x41, 0x41, 0x41, 0x41
		  };
		
		printf("receiveICMP:receive len %u:", len);
		printbuf((unsigned char *)buffer, len);
		printf("\r\n");

		
		forwardPacketBack_udp(sd_forward, buffer, len);
	
      }
    }
  }

  return NULL;
}

void printbuf(unsigned char* buf, int len)
{
	for(int i=0;i<len;i++)
	{
		if(i%16==0)
		{
			printf("\r\n");
		}
		printf("0x%.2x ",buf[i]);

	}
}
void printip(unsigned char* buf, int len)
{
	for(int i=0;i<len;i++)
	{

		printf("%d ",buf[i]);
		if(i!=3)
		{
			printf(".");
		}
	}
}


// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char *argv[]) {

  if (argc == 1) {
    type = 0;
  }
 else  if (argc == 2) {
     type = atoi(argv[1]);
  }
 else  if (argc == 3) {
     type = atoi(argv[1]);
     allowed_peer_IpAddr= inet_addr(argv[2]);
  } 
  else{
    printf("- Invalid parameters!!!\r\n");
    printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP>%d <target port>\r\n", argv[0], argc);
    exit(-1);
  }  
  //unsigned long src_addr = inet_addr(argv[1]);
  //unsigned long dst_addr = inet_addr(argv[3]);

  //unsigned short src_port = htons(atoi(argv[2]));
  //unsigned short dst_port = htons(atoi(argv[4]));
  

  // Create a raw socket with UDP protocol----
  //int sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  // IPPROTO_IP说明用户自己填写IP报文
  // IP_HDRINCL表示由内核来计算IP报文的头部校验和，和填充那个IP的id
  int val = 1;
  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)))	{
    perror("setsockopt() error");
    close(sd);
    return -1;
  }
  
  printf("socket() - Using SOCK_RAW socket and IP protocol is OK.\n");
  
	int forwardfd;
	if ((forwardfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	    perror("open forwardfd socket");
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(7000);
	if (bind(forwardfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	    perror("bind");
	}


  int sd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

 // if (setsockopt(sd_icmp, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)))	{
  //  perror("setsockopt() error");
   // close(sd_icmp);
   // return -1;
  //}

  int sd_ip =socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

  printf("socket() - Using SOCK_RAW socket and IP protocol is OK.type=%d\n", type);
  // ----

  // Create a raw socket with MAC protocol----
  /*int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); // all packet htons(ETH_P_ALL)
  int one = 1;
  const int *val = &one;
  if (sd < 0)	{
    perror("socket() error");
    // If something wrong just exit
    return -1;
  }
  printf("socket(%d) - Using SOCK_RAW socket and ETH_P_IP protocol is OK.\n", sd);*/
  // ----

  /*struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(socket_address));
  socket_address.sll_ifindex = if_nametoindex("ens2");
  socket_address.sll_halen = ETH_ALEN;
  if (bind(sd, (struct sockaddr *)&socket_address, sizeof(socket_address))) {
    perror("bind() error");
    close(sd);
    return -1;
  }*/

	key_t key = ftok("/",100);
	if(key < 0){
		perror("ftok");
		return 1;
	}
	//msgid = msgget(key,IPC_CREAT|IPC_EXCL|0666);
	msgid = msgget(key,IPC_CREAT);
	//msgctl(msgid,IPC_RMID,NULL)
		
	struct sd_all sdall;
	sdall.sd_icmp = sd_icmp;
	sdall.sd_raw= sd;
	sdall.sd_forward=forwardfd;
	sdall.sd_ip=sd_ip;


  pthread_t thdRcv;
  isRun = true;
  if (pthread_create(&thdRcv, NULL, receiveAllPacket, (void *)&sdall) != 0) {
    printf("create thread failed!\r\n");
    return -1;
  }
  pthread_t thdSend;
  if (pthread_create(&thdSend, NULL, sendAllPacket, (void *)&sdall) != 0) {
    printf("create thread failed!\r\n");
    return -1;
  }
  
  //pthread_t thdRcv_icmp;
  //if (pthread_create(&thdRcv_icmp, NULL, receiveICMP,(void *)&sdall) != 0) {
  //  printf("create icmp thread failed!\r\n");
  //  return -1;
 // }
  //src_addr = srcIpAddr;
  //dst_addr = dstIpAddr;
  //src_port = htons(6000);
  //dst_port = htons(10000);
  //sendudp(sd, src_addr, src_port, dst_addr, dst_port);
  //sendpacket(sd, src_addr, dst_addr);

    //while (true) {
     // sleep(2);
      //}

  if (pthread_join(thdRcv, NULL)) {
    printf("join thread fail!\r\n");
  }
  if (pthread_join(thdSend, NULL)) {
    printf("join thread fail!\r\n");
  }
  close(sd);
    isRun = false;
  return 0;
}
