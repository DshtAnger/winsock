#include<stdio.h>
#include<winsock2.h>
#include <conio.h>
#include<iostream.h>
#pragma comment(lib,"ws2_32.lib")//连接动态库

/*#define CLIENTSEND_EXIT 1
#define CLIENTSEND_TRAN 2
#define CLIENTSEND_LIST 3
#define SERVERSEND_SELFID 1
#define SERVERSEND_NEWUSER 2
#define SERVERSEND_SHOWMSG 3
#define SERVERSEND_ONLINE 4*/
FILE *ioutfileServer;//服务端消息记录
FILE *ioutfileClient;//客户端消息记录

//函数声明

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
	WORD sockVersion = MAKEWORD(2,2);	//指定版本号
	WSADATA wsd;                      //指向WSADATA数据结构的指针，用来接收Windows Sockets实现的细节
	if(WSAStartup(sockVersion,&wsd)!=0)          //判断初始化动态链接库是否成功
	{
		printf("初始化失败,请重试\n");
		return 0;
	}
	
	do
	{
		printf("选择程序类型:\n");
		printf("服务端:1\n");
		printf("客户端:2\n\n");
		printf("请选择:");
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
	struct sockaddr_in serveraddr;           //服务器本地地址信息
	struct sockaddr_in serveraddrfrom;      //连接的客户端地址信息
	int iPort=4600;
	int iBindResult=-1;
	int iWhileCount=10; //绑定端口失败时的重试次数
	
	struct hostent* localHost;//定义用来获取服务端主机信息的结构体指针
	char* localIP;//接收经转换后的点分十进制地址
	
	SOCKET m_Server;//客户端接入后用来通信的新socket
	
	char cWelcomeBuffer[]="请输入用户名和密码(用回车分隔):\0";
	int len=sizeof(struct sockaddr);
	int iWhileListenCount=10;
	DWORD nThreadid=0;   
	int ires;   //发送的返回值
	int iRecvResult;//认证时接收消息的返回值
	char cSendBuffer[1024];  //发送消息缓存
	char cShowBuffer[1024]; //接收消息缓存
	ioutfileServer=fopen("MessageServer.txt","a");

	m_SockServer=socket(AF_INET,SOCK_STREAM,0);//创建套接字
	
	//绑定端口号
	printf("本机绑定的端口号（大于1024）:");
	scanf("%d",&iPort);
	
	localHost=gethostbyname("");	
	localIP=inet_ntoa(*(struct in_addr*)*localHost->h_addr_list ); 
	//inet_ntoa用以将*(struct in_addr*)*localHost->h_addr_list获取的网络字节序排序的主机地址转换成点分十进制的地址形式
	

	//设置网络地址信息
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(iPort);          //把16位值从主机字节序转换成网络字节序    
	serveraddr.sin_addr.S_un.S_addr=inet_addr(localIP);//将字符串表示的点分十进制形式地址转换为32位的无符号长整型数据	
	


	//绑定地址信息
	iBindResult=bind(m_SockServer,(struct sockaddr*)&serveraddr,sizeof(struct sockaddr));//若成功则返回0

	
	//如果端口不能绑定，重新设置端口
	while(iBindResult!=0&&iWhileCount>0)
	{
		printf("绑定失败，重新输入:");
		scanf("%d",&iPort);
		serveraddr.sin_family=AF_INET;
		serveraddr.sin_port=htons(iPort);
		serveraddr.sin_addr.S_un.S_addr=inet_addr(localIP);
		iBindResult=bind(m_SockServer,(struct sockaddr*)&serveraddr,sizeof(struct sockaddr));
		iWhileCount--;

		if(iWhileCount<=0)
		{
			printf("绑定端口失败，重新运行程序\n");
			exit(0);
		}

	}

	printf("本机的IP地址为:%s\n\n",inet_ntoa(serveraddr.sin_addr));
	
		

	
	
	if(listen(m_SockServer,10) == SOCKET_ERROR)	//10为等待连接的最大队列长度
    {
        printf("监听失败，请重试\n");
        exit(0);
    }


	
	
	while(iWhileListenCount>0)
	{
		printf("开始监听,等待连接……\n");
		
		m_Server=accept(m_SockServer,(struct sockaddr*)&serveraddrfrom,&len);//用处于监听的套接字创建新的用于接受客户端连接的套接字
		
		if(m_Server!=INVALID_SOCKET)
		{
			//连接成功，发送欢迎消息
			printf("接收到一个地址%为%s的连接\n\n", inet_ntoa(serveraddrfrom.sin_addr));			
			send(m_Server,cWelcomeBuffer,sizeof(cWelcomeBuffer),0);
			break;
								
		}
		
		printf(".");
		iWhileListenCount--;
		

		if(iWhileListenCount<=0)
		{
			printf("\n建立连接失败\n");
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
			send(m_Server, "succeed", strlen("succeed"), 0);//用以防止先输错的情况下客户端缓冲区始终保留wrong而导致后续正确输入无法通过
			break;
		}

		
		if (Check==0)
		{
			send(m_Server, "wrong", strlen("wrong"), 0);
		}

		memset(cShowBuffer,0,1024);//清空接收用户名密码缓冲区,防止上一次数据影响下一次数据的完整接收
		
		//重启认证文本,使匹配时可以重新遍历所有记录
		fclose(fp);
		fp = fopen(fileName, "rb");
			


	}

	

	fclose(fp);
	printf("用户身份认证成功\n");
	//send(m_Server, "\n", strlen("\n"), 0);




	//启动接收消息的线程
	CreateThread(NULL,0,threadproServer,(LPVOID)m_Server,0,&nThreadid);



//发送消息部分
	while(1)
	{
		//memset(cSendBuffer,0,1024);		//把cSendBuffer前1024位置为0
		//scanf("%s",cSendBuffer);       
		
		gets(cSendBuffer);//输入消息

		if(strlen(cSendBuffer)>0)      //消息不能为空
		{
			ires=send(m_Server,cSendBuffer,strlen(cSendBuffer),0);   //发送消息

			if(ires<0)
			{
				printf("发送失败");
			}
			else
			{
				 sprintf(cShowBuffer,cSendBuffer);
				//sprintf(cShowBuffer,"Send to:%s\n",cSendBuffer);//将cSendBuffer中数据连在Send to:后写入cShowBuffer
				//printf("%s",cShowBuffer);
				fwrite(cShowBuffer,sizeof(char),strlen(cShowBuffer),ioutfileServer);
			}  //将cShowBuffer地址开始的信息写入ioutfileServer所指文日志，每次写char字节到，进行strlen(cShowBuffer)次

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
	int iWhileIP=10;  //循环次数
	int iCnnRes;    //连接结果
	DWORD nThreadid=0; //线程ID值
	char cSendBuffer[1024];    //发送缓存
	char cShowBuffer[1024];    //显示缓存
	char cRecvBuffer[1024];    //接收缓存

	int num;                   //接收的字符个数
	int ires;                  //发送消息的结果
	//int iIPRes;                //检测IP是否正确

m_SockClient=socket(AF_INET,SOCK_STREAM,0);
printf("请输入服务器地址:");
scanf("%s",cServerIP);
printf("请输入服务器端口:");
scanf("%d",&cServerPort);

//IP地址判断
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
		printf("请重新输入服务器地址:\n");
		scanf("%s",cServerIP);
		iIPRes=CheckIP(cServerIP);
		iWhileIP--;
		if(iWhileIP<=0)
		{
			printf("输入次数过多\n");
			exit(0);
		}
	}
}*/

ioutfileClient=fopen("MessageServerClient.txt","a");

clientaddr.sin_family=AF_INET;
clientaddr.sin_port=htons(cServerPort);   //应与服务端绑定的端口一致
clientaddr.sin_addr.S_un.S_addr=inet_addr(cServerIP);

iCnnRes=connect(m_SockClient,(struct sockaddr*)&clientaddr,sizeof(struct sockaddr));

if(iCnnRes==0) //连接成功
{
	num=recv(m_SockClient,cRecvBuffer,1024,0);  //接收消息

	if(num>0)
	{
		printf("Receive from server:%s\n",cRecvBuffer);
		
	}
	else
	{
	printf("连接不正确\n");
	}




}
	




	char input[1024];
	AuthenticationInput(input);//用户名输入和带*显示的密码输入

	send(m_SockClient,input,strlen(input), 0);
	
	ires = recv(m_SockClient, cSendBuffer, 1024, 0);
	cSendBuffer[ires] = '\0';
	
	while (*cSendBuffer == *"wrong")
	{
		printf("用户不存在或密码错误，等3秒重新输入\n");
		Sleep(3000);
		AuthenticationInput(input);
		send(m_SockClient,input,strlen(input), 0);
		ires = recv(m_SockClient, cSendBuffer, 1024, 0);
		cSendBuffer[ires] = '\0';
	}


	printf("认证成功,欢迎使用\n");
	
	
	
	//启动接收消息线程
	CreateThread(NULL,0,threadproClient,(LPVOID)m_SockClient,0,&nThreadid);
	



while(1)
	{
			
		
		//memset(cSendBuffer,0,1024);
		//scanf("%s",cSendBuffer);
		
		gets(cSendBuffer);//输入消息
		
		if(strlen(cSendBuffer)>0)      //消息不能为空
		{
				ires=send(m_SockClient,cSendBuffer,strlen(cSendBuffer),0);   //发送消息

			if(ires<0)
			{
				printf("发送失败");
			}
			else
			{
				sprintf(cShowBuffer,cSendBuffer);
				
				//sprintf(cShowBuffer,"Send to:%s\n",cSendBuffer);//将cSendBuffer中数据连在Send to:后写入cShowBuffer
				//printf("%s",cShowBuffer);
				fwrite(cShowBuffer,sizeof(char),strlen(cShowBuffer),ioutfileClient);
				fflush(ioutfileClient);
		}                                  //将消息写入日志

			if(strcmp("exit",cSendBuffer)==0)
			{
			
				ExitSystem();
			}
		}
	}
}









DWORD WINAPI threadproServer(LPVOID pParam)//服务器端接收消息的线程
{
	SOCKET hsock=(SOCKET)pParam;
	char cRecvBuffer[1024];
	char cShowBuffer[1024];
	int num=0;
	
	if(hsock!=INVALID_SOCKET)
		printf("Start:\n");
	
	while(1)
	{
		num=recv(hsock,cRecvBuffer,1024,0); //接收消息
		if(num>=0)
		{
			cRecvBuffer[num]='\0';
			sprintf(cShowBuffer,"the client to me:%s\n",cRecvBuffer);
			printf("%s",cShowBuffer);
			//记录消息
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



DWORD WINAPI threadproClient(LPVOID pParam)//客户端接收消息的线程
{
	SOCKET hsock=(SOCKET)pParam;
	char cRecvBuffer[1024];
	char cShowBuffer[1024];
	int num=0;
	
	if(hsock!=INVALID_SOCKET)
		printf("Start:\n");
	
	while(1)
	{
		num=recv(hsock,cRecvBuffer,1024,0); //接收消息
		if(num>=0)
		{
			cRecvBuffer[num]='\0';
			sprintf(cShowBuffer,"the server to me:%s\n",cRecvBuffer);
			printf("%s",cShowBuffer);
			//记录消息
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




void ExitSystem()  //用于点对点方式的退出
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
	char IPAddress[128];//IP地址字符串 
	char IPNumber[4];//IP地址中每组的数值
	int iSubIP=0;       //IP地址中四段之一
	int iDot=0;          //IP地址中 “.”的个数
	int iResult=0;
	int iIPResult=1;
	int i;  //循环控制变量
	

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






