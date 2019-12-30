// MyTracert02.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Winsock2.h>
using namespace std;
typedef ULONG IPAddr;       // An IP address.

typedef struct ip_option_information {
	UCHAR   Ttl;                // Time To Live
	UCHAR   Tos;                // Type Of Service
	UCHAR   Flags;              // IP header flags
	UCHAR   OptionsSize;        // Size in bytes of options data
	UCHAR* OptionsData;        // Pointer to options data
} IP_OPTION_INFORMATION, * PIP_OPTION_INFORMATION;

typedef struct icmp_echo_reply {
	IPAddr  Address;            // Replying address
	ULONG   Status;             // Reply IP_STATUS
	ULONG   RoundTripTime;      // RTT in milliseconds
	USHORT  DataSize;           // Reply data size in bytes
	USHORT  Reserved;           // Reserved for system use
	PVOID   Data;               // Pointer to the reply data
	struct ip_option_information Options; // Reply options
} ICMP_ECHO_REPLY, * PICMP_ECHO_REPLY;

typedef HANDLE(WINAPI* lpIcmpCreateFile)(VOID);
typedef BOOL(WINAPI* lpIcmpCloseHandle)(HANDLE IcmpHandle);
typedef DWORD(WINAPI* lpIcmpSendEcho)(HANDLE IcmpHandle, IPAddr DestinationAddress,
	LPVOID RequestData, WORD RequestSize,
	PIP_OPTION_INFORMATION RequestOptions,
	LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout);

///////////////////////////////////////////////////////////////////////////////////////////

const int DEF_MAX_HOP = 30;		//最大跳站数
const int DATA_SIZE = 32;		//ICMP包数据字段大小
const DWORD TIMEOUT = 3000;		//超时时间，单位ms

#pragma comment (lib,"Ws2_32.lib")

int main(int argc, char* argv[])
{
	if (argc != 2)
	{

		cout << "请输入IP地址或主机名：\n";
		char temp[64];
		cin >> temp;
		argv[1] = temp;
	}

	//初始化winsock2环境
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		cerr << "Failed to initialize the WinSock2 DLL\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	//将命令行参数转换为IP地址
	ULONG DestIp = inet_addr(argv[1]);
	if (DestIp == INADDR_NONE)
	{
		//转换不成功时按域名解析
		hostent* pHost = gethostbyname(argv[1]);
		if (pHost)
		{
			DestIp = (*(in_addr*)pHost->h_addr).s_addr;
		}
		else
		{
			cout << "Unable to resolve the target name " << argv[1] << endl;
			WSACleanup();
			return -1;
		}
	}

	//载入ICMP.DLL动态库
	HMODULE hInst = LoadLibrary(L"ICMP.dll");
	if (!hInst)
	{
		cout << "Could not load up the ICMP DLL\n";
		WSACleanup();
		return -1;
	}

	//获取所需的三个函数指针
	lpIcmpCreateFile IcmpCreateFile = (lpIcmpCreateFile)GetProcAddress(hInst, "IcmpCreateFile");
	lpIcmpSendEcho IcmpSendEcho = (lpIcmpSendEcho)GetProcAddress(hInst, "IcmpSendEcho");
	lpIcmpCloseHandle IcmpCloseHandle = (lpIcmpCloseHandle)GetProcAddress(hInst, "IcmpCloseHandle");
	if (IcmpCreateFile == NULL || IcmpSendEcho == NULL || IcmpCloseHandle == NULL)
	{
		cout << "Could not find ICMP functions in the ICMP DLL\n";
		WSACleanup();
		return -1;
	}

	//打开ICMP句柄
	HANDLE hIcmp = IcmpCreateFile();
	if (hIcmp == INVALID_HANDLE_VALUE)
	{
		cout << "Could not get a valid ICMP handle\n";
		WSACleanup();
		return -1;
	}

	cout << "\nTracing route to " << argv[1] << " [" << inet_ntoa(*(in_addr*)(&DestIp))
		<< "] with a maximum of " << DEF_MAX_HOP << " hops.\n" << endl;

	//设置IP报头TTL值
	IP_OPTION_INFORMATION IpOption; //该结构用来控制所发ICMP数据包的IP报头相应字段值
	ZeroMemory(&IpOption, sizeof(IP_OPTION_INFORMATION));
	IpOption.Ttl = 1;

	//设置要发送的ICMP数据
	char SendData[DATA_SIZE];
	memset(SendData, 'E', sizeof(SendData));

	//设置接收缓冲区
	char ReplyBuffer[sizeof(ICMP_ECHO_REPLY) + DATA_SIZE];
	ICMP_ECHO_REPLY* pEchoReply = (ICMP_ECHO_REPLY*)ReplyBuffer;

	BOOL bLoop = TRUE;
	int iMaxHop = DEF_MAX_HOP;
	while (bLoop && iMaxHop--)
	{
		//打印序号
		cout << (int)IpOption.Ttl << "   ";

		//发送ICMP回显包并接收应答
		if (IcmpSendEcho(hIcmp, DestIp, SendData, sizeof(SendData), &IpOption, ReplyBuffer, sizeof(ReplyBuffer), TIMEOUT) != 0)
		{
			//正确收到应答包，打印时间和IP地址
			if (pEchoReply->RoundTripTime == 0)
			{
				cout << "\t<1 ms";
			}
			else
			{
				cout << "\t" << pEchoReply->RoundTripTime << " ms";
			}
			cout << "\t" << inet_ntoa(*(in_addr*) & (pEchoReply->Address)) << endl;

			//判断是否完成路由路径探测
			if (pEchoReply->Address == DestIp)
			{
				cout << "\nTrace complete.\n" << endl;
				bLoop = FALSE;
			}
		}
		else //超时返回,打印代表超时的"*"
		{
			cout << "\t" << "*" << "\tRequest timed out." << endl;
		}

		//TTL值加1
		IpOption.Ttl++;
	}
	IcmpCloseHandle(hIcmp);
	WSACleanup();
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
