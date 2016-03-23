#include<stdio.h>
#include<winsock2.h>
#include <conio.h>
#include<iostream.h>
#pragma comment(lib,"ws2_32.lib")//���Ӷ�̬��

/*#define CLIENTSEND_EXIT 1
#define CLIENTSEND_TRAN 2
#define CLIENTSEND_LIST 3
#define SERVERSEND_SELFID 1
#define SERVERSEND_NEWUSER 2
#define SERVERSEND_SHOWMSG 3
#define SERVERSEND_ONLINE 4*/
FILE *ioutfileServer;//�������Ϣ��¼
FILE *ioutfileClient;//�ͻ�����Ϣ��¼

//��������

DWORD WINAPI threadproServer(LPVOID pParam);
DWORD WINAPI threadproClient(LPVOID pParam);
void CreateServer(void);
void CreateClient(void);                   
int CheckIP(char *);
void ExitSystem(void);
int AuthenticationMatch(char *string,FILE * fp);
void AuthenticationInput(char *input);





int main(void)
{
	int iSel=0;
	WORD sockVersion = MAKEWORD(2,2);	//ָ���汾��
	WSADATA wsd;                      //ָ��WSADATA���ݽṹ��ָ�룬��������Windows Socketsʵ�ֵ�ϸ��
	if(WSAStartup(sockVersion,&wsd)!=0)          //�жϳ�ʼ����̬���ӿ��Ƿ�ɹ�
	{
		printf("��ʼ��ʧ��,������\n");
		return 0;
	}
	
	do
	{
		printf("ѡ���������:\n");
		printf("�����:1\n");
		printf("�ͻ���:2\n\n");
		printf("��ѡ��:");
		scanf("%d",&iSel);
		printf("\n");
	}while(iSel<0||iSel>2);
	
	
	switch(iSel)
	{
	case 1:	
		CreateServer();
		break;
	case 2:
		CreateClient();
		break;
	}

printf("Log off the system\n");

return 0;

}




void CreateServer()
{
	SOCKET m_SockServer;
	struct sockaddr_in serveraddr;           //���������ص�ַ��Ϣ
	struct sockaddr_in serveraddrfrom;      //���ӵĿͻ��˵�ַ��Ϣ
	int iPort=4600;
	int iBindResult=-1;
	int iWhileCount=10; //�󶨶˿�ʧ��ʱ�����Դ���
	
	struct hostent* localHost;//����������ȡ�����������Ϣ�Ľṹ��ָ��
	char* localIP;//���վ�ת����ĵ��ʮ���Ƶ�ַ
	
	SOCKET m_Server;//�ͻ��˽��������ͨ�ŵ���socket
	
	char cWelcomeBuffer[]="�������û���������(�ûس��ָ�):\0";
	int len=sizeof(struct sockaddr);
	int iWhileListenCount=10;
	DWORD nThreadid=0;   
	int ires;   //���͵ķ���ֵ
	int iRecvResult;//��֤ʱ������Ϣ�ķ���ֵ
	char cSendBuffer[1024];  //������Ϣ����
	char cShowBuffer[1024]; //������Ϣ����
	ioutfileServer=fopen("MessageServer.txt","a");

	m_SockServer=socket(AF_INET,SOCK_STREAM,0);//�����׽���
	
	//�󶨶˿ں�
	printf("�����󶨵Ķ˿ںţ�����1024��:");
	scanf("%d",&iPort);
	
	localHost=gethostbyname("");	
	localIP=inet_ntoa(*(struct in_addr*)*localHost->h_addr_list ); 
	//inet_ntoa���Խ�*(struct in_addr*)*localHost->h_addr_list��ȡ�������ֽ��������������ַת���ɵ��ʮ���Ƶĵ�ַ��ʽ
	

	//���������ַ��Ϣ
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(iPort);          //��16λֵ�������ֽ���ת���������ֽ���    
	serveraddr.sin_addr.S_un.S_addr=inet_addr(localIP);//���ַ�����ʾ�ĵ��ʮ������ʽ��ַת��Ϊ32λ���޷��ų���������	
	


	//�󶨵�ַ��Ϣ
	iBindResult=bind(m_SockServer,(struct sockaddr*)&serveraddr,sizeof(struct sockaddr));//���ɹ��򷵻�0

	
	//����˿ڲ��ܰ󶨣��������ö˿�
	while(iBindResult!=0&&iWhileCount>0)
	{
		printf("��ʧ�ܣ���������:");
		scanf("%d",&iPort);
		serveraddr.sin_family=AF_INET;
		serveraddr.sin_port=htons(iPort);
		serveraddr.sin_addr.S_un.S_addr=inet_addr(localIP);
		iBindResult=bind(m_SockServer,(struct sockaddr*)&serveraddr,sizeof(struct sockaddr));
		iWhileCount--;

		if(iWhileCount<=0)
		{
			printf("�󶨶˿�ʧ�ܣ��������г���\n");
			exit(0);
		}

	}

	printf("������IP��ַΪ:%s\n\n",inet_ntoa(serveraddr.sin_addr));
	
		

	
	
	if(listen(m_SockServer,10) == SOCKET_ERROR)	//10Ϊ�ȴ����ӵ������г���
    {
        printf("����ʧ�ܣ�������\n");
        exit(0);
    }


	
	
	while(iWhileListenCount>0)
	{
		printf("��ʼ����,�ȴ����ӡ���\n");
		
		m_Server=accept(m_SockServer,(struct sockaddr*)&serveraddrfrom,&len);//�ô��ڼ������׽��ִ����µ����ڽ��ܿͻ������ӵ��׽���
		
		if(m_Server!=INVALID_SOCKET)
		{
			//���ӳɹ������ͻ�ӭ��Ϣ
			printf("���յ�һ����ַ%Ϊ%s������\n\n", inet_ntoa(serveraddrfrom.sin_addr));			
			send(m_Server,cWelcomeBuffer,sizeof(cWelcomeBuffer),0);
			break;
								
		}
		
		printf(".");
		iWhileListenCount--;
		

		if(iWhileListenCount<=0)
		{
			printf("\n��������ʧ��\n");
			exit(0);
		}
	
	}



	






	int Check=0;
	
	FILE *fp;
	char *fileName="Authentication.txt";

	if ((fp = fopen(fileName, "rb")) == 0)
	{
		printf("Can't open %s, program will to exit.", fileName);
		exit(1);
	}
	else
	{
		printf("succeed to open %s\n", fileName);
	}

	
	
	while (Check==0)
	{
		iRecvResult=recv(m_Server,cShowBuffer,1024, 0);
		
		if (iRecvResult>=0)
		{
			
			cShowBuffer[iRecvResult] = '\0';
		}
	
		
		Check=AuthenticationMatch(cShowBuffer,fp);

		if(Check==1)
		{
			send(m_Server, "succeed", strlen("succeed"), 0);//���Է�ֹ����������¿ͻ��˻�����ʼ�ձ���wrong�����º�����ȷ�����޷�ͨ��
			break;
		}

		
		if (Check==0)
		{
			send(m_Server, "wrong", strlen("wrong"), 0);
		}

		memset(cShowBuffer,0,1024);//��ս����û������뻺����,��ֹ��һ������Ӱ����һ�����ݵ���������
		
		//������֤�ı�,ʹƥ��ʱ�������±������м�¼
		fclose(fp);
		fp = fopen(fileName, "rb");
			


	}

	

	fclose(fp);
	printf("�û������֤�ɹ�\n");
	//send(m_Server, "\n", strlen("\n"), 0);




	//����������Ϣ���߳�
	CreateThread(NULL,0,threadproServer,(LPVOID)m_Server,0,&nThreadid);



//������Ϣ����
	while(1)
	{
		//memset(cSendBuffer,0,1024);		//��cSendBufferǰ1024λ��Ϊ0
		//scanf("%s",cSendBuffer);       
		
		gets(cSendBuffer);//������Ϣ

		if(strlen(cSendBuffer)>0)      //��Ϣ����Ϊ��
		{
			ires=send(m_Server,cSendBuffer,strlen(cSendBuffer),0);   //������Ϣ

			if(ires<0)
			{
				printf("����ʧ��");
			}
			else
			{
				 sprintf(cShowBuffer,cSendBuffer);
				//sprintf(cShowBuffer,"Send to:%s\n",cSendBuffer);//��cSendBuffer����������Send to:��д��cShowBuffer
				//printf("%s",cShowBuffer);
				fwrite(cShowBuffer,sizeof(char),strlen(cShowBuffer),ioutfileServer);
			}  //��cShowBuffer��ַ��ʼ����Ϣд��ioutfileServer��ָ����־��ÿ��дchar�ֽڵ�������strlen(cShowBuffer)��

			if(strcmp("exit",cSendBuffer)==0)
			{
			
				ExitSystem();
			}
		}
	}
	
}


void CreateClient()
{
	SOCKET m_SockClient;
	struct sockaddr_in clientaddr;
	char cServerIP[128];
	int cServerPort;
	int iWhileIP=10;  //ѭ������
	int iCnnRes;    //���ӽ��
	DWORD nThreadid=0; //�߳�IDֵ
	char cSendBuffer[1024];    //���ͻ���
	char cShowBuffer[1024];    //��ʾ����
	char cRecvBuffer[1024];    //���ջ���

	int num;                   //���յ��ַ�����
	int ires;                  //������Ϣ�Ľ��
	//int iIPRes;                //���IP�Ƿ���ȷ

m_SockClient=socket(AF_INET,SOCK_STREAM,0);
printf("�������������ַ:");
scanf("%s",cServerIP);
printf("������������˿�:");
scanf("%d",&cServerPort);

//IP��ַ�ж�
/*if(strlen(cServerIP)==0)
{
	strcpy(cServerIP,"127.0.0.1");
}
else
{
	iIPRes=CheckIP(cServerIP);
	//printf("%d",iIPRes);
	while(iIPRes&&iWhileIP>0)
	{
		printf("�����������������ַ:\n");
		scanf("%s",cServerIP);
		iIPRes=CheckIP(cServerIP);
		iWhileIP--;
		if(iWhileIP<=0)
		{
			printf("�����������\n");
			exit(0);
		}
	}
}*/

ioutfileClient=fopen("MessageServerClient.txt","a");

clientaddr.sin_family=AF_INET;
clientaddr.sin_port=htons(cServerPort);   //Ӧ�����˰󶨵Ķ˿�һ��
clientaddr.sin_addr.S_un.S_addr=inet_addr(cServerIP);

iCnnRes=connect(m_SockClient,(struct sockaddr*)&clientaddr,sizeof(struct sockaddr));

if(iCnnRes==0) //���ӳɹ�
{
	num=recv(m_SockClient,cRecvBuffer,1024,0);  //������Ϣ

	if(num>0)
	{
		printf("Receive from server:%s\n",cRecvBuffer);
		
	}
	else
	{
	printf("���Ӳ���ȷ\n");
	}




}
	




	char input[1024];
	AuthenticationInput(input);//�û�������ʹ�*��ʾ����������

	send(m_SockClient,input,strlen(input), 0);
	
	ires = recv(m_SockClient, cSendBuffer, 1024, 0);
	cSendBuffer[ires] = '\0';
	
	while (*cSendBuffer == *"wrong")
	{
		printf("�û������ڻ�������󣬵�3����������\n");
		Sleep(3000);
		AuthenticationInput(input);
		send(m_SockClient,input,strlen(input), 0);
		ires = recv(m_SockClient, cSendBuffer, 1024, 0);
		cSendBuffer[ires] = '\0';
	}


	printf("��֤�ɹ�,��ӭʹ��\n");
	
	
	
	//����������Ϣ�߳�
	CreateThread(NULL,0,threadproClient,(LPVOID)m_SockClient,0,&nThreadid);
	



while(1)
	{
			
		
		//memset(cSendBuffer,0,1024);
		//scanf("%s",cSendBuffer);
		
		gets(cSendBuffer);//������Ϣ
		
		if(strlen(cSendBuffer)>0)      //��Ϣ����Ϊ��
		{
				ires=send(m_SockClient,cSendBuffer,strlen(cSendBuffer),0);   //������Ϣ

			if(ires<0)
			{
				printf("����ʧ��");
			}
			else
			{
				sprintf(cShowBuffer,cSendBuffer);
				
				//sprintf(cShowBuffer,"Send to:%s\n",cSendBuffer);//��cSendBuffer����������Send to:��д��cShowBuffer
				//printf("%s",cShowBuffer);
				fwrite(cShowBuffer,sizeof(char),strlen(cShowBuffer),ioutfileClient);
				fflush(ioutfileClient);
		}                                  //����Ϣд����־

			if(strcmp("exit",cSendBuffer)==0)
			{
			
				ExitSystem();
			}
		}
	}
}









DWORD WINAPI threadproServer(LPVOID pParam)//�������˽�����Ϣ���߳�
{
	SOCKET hsock=(SOCKET)pParam;
	char cRecvBuffer[1024];
	char cShowBuffer[1024];
	int num=0;
	
	if(hsock!=INVALID_SOCKET)
		printf("Start:\n");
	
	while(1)
	{
		num=recv(hsock,cRecvBuffer,1024,0); //������Ϣ
		if(num>=0)
		{
			cRecvBuffer[num]='\0';
			sprintf(cShowBuffer,"the client to me:%s\n",cRecvBuffer);
			printf("%s",cShowBuffer);
			//��¼��Ϣ
			fwrite(cShowBuffer,sizeof(char),strlen(cShowBuffer),ioutfileServer);
			fflush(ioutfileServer);
			if(strcmp("exit",cRecvBuffer)==0)
			{
				ExitSystem();
			}
		}
	}

	return 0;
}



DWORD WINAPI threadproClient(LPVOID pParam)//�ͻ��˽�����Ϣ���߳�
{
	SOCKET hsock=(SOCKET)pParam;
	char cRecvBuffer[1024];
	char cShowBuffer[1024];
	int num=0;
	
	if(hsock!=INVALID_SOCKET)
		printf("Start:\n");
	
	while(1)
	{
		num=recv(hsock,cRecvBuffer,1024,0); //������Ϣ
		if(num>=0)
		{
			cRecvBuffer[num]='\0';
			sprintf(cShowBuffer,"the server to me:%s\n",cRecvBuffer);
			printf("%s",cShowBuffer);
			//��¼��Ϣ
			fwrite(cShowBuffer,sizeof(char),strlen(cShowBuffer),ioutfileClient);
			fflush(ioutfileClient);
			if(strcmp("exit",cRecvBuffer)==0)
			{
				ExitSystem();
			}
		}
	}

	return 0;
}




void ExitSystem()  //���ڵ�Ե㷽ʽ���˳�
{

	if(ioutfileServer!=NULL)
		fclose(ioutfileServer);
	if(ioutfileClient!=NULL)
		fclose(ioutfileClient);
	
	WSACleanup();
	exit(0);
}








int CheckIP(char *cIP)
{
	char IPAddress[128];//IP��ַ�ַ��� 
	char IPNumber[4];//IP��ַ��ÿ�����ֵ
	int iSubIP=0;       //IP��ַ���Ķ�֮һ
	int iDot=0;          //IP��ַ�� ��.���ĸ���
	int iResult=0;
	int iIPResult=1;
	int i;  //ѭ�����Ʊ���
	

	memset(IPNumber,0,4);
	strncmp(IPAddress,cIP,128);
	for(i=0;i<128;i++)
	{
		if(IPAddress[i]=='.')
		{
			iDot++;
			iSubIP=0;
			if(atoi(IPNumber)>255)
				iIPResult=0;
			memset(IPNumber,0,4);
		}
		else
		{
			IPNumber[iSubIP++]=IPAddress[i];
		}
		if(iDot==3&&iIPResult!=0)
			iResult=1;
	}

	return iResult;
}
	





int AuthenticationMatch(char *string,FILE *fp)
{
	char a[100];                                      //char *fgets(char *buf, int bufsize, FILE *stream);
	                                                  
	//fgets(a, 100, fp);	
	while ((fgets(a, 100, fp))!=NULL)
	{
		int t=strlen(a);
		a[strlen(a)-2] = '\0';
		if ((strcmp(a, string)) == 0)
			return 1;
				
	}
	return 0;
}





void AuthenticationInput(char *input)
{	
		scanf("%s",input);
		int i=strlen(input);
		input[i]=' ';
		i++;
	
	for(;;)
	{
		input[i]=getch();
		
		if (input[i]!='\r')
			putchar('*');
		else
		{
			input[i]='\0';
			break;
		}
		i++;
	}

	printf("\n");
}






