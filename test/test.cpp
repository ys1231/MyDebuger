// 测试程序.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<windows.h>

int g_nmuber = 0;

bool PEB_BegingDebugged();
bool NQIP_ProcessDebugFlag();
int main()
{
	_asm int 3;

	for (int i = 0; i < 10; ++i) {
		//00453857
		printf("hello");
	}

	//00453866    全局变量[0515E3Ch]
	g_nmuber = 90;

	//00453870 getchar
	getchar();

	//反调试
	if (PEB_BegingDebugged())
	{
		MessageBox(0, L"Begindebugged : 有调试器-----\n", 0, 0);
	}
	else {
		MessageBox(0, L"Begindebugged : 安全度过-----\n", 0, 0);
	}
	if (NQIP_ProcessDebugFlag())
	{
		MessageBox(0, L"NtQueryInformationProcess Debugflag : 有调试器-----\n", 0, 0);
	}
	else {
		MessageBox(0, L"NtQueryInformationProcess Debugflag :  安全度过-----\n", 0, 0);
	}

	printf("运行结束\n");
}

bool PEB_BegingDebugged()
{
	bool BegingDebugged = false;
	__asm
	{
		MOV EAX, DWORD PTR FS : [0x30] ;    // 获取PEB地址
		MOV AL, BYTE PTR DS : [EAX + 0x02] ; // 获取PEB.BegingD...
		MOV BegingDebugged, AL;
	}
	return BegingDebugged;
}

#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
bool NQIP_ProcessDebugFlag()
{
	BOOL bProcessDebugFlag = 0;
	NtQueryInformationProcess(
		GetCurrentProcess(), 		// 目标进程句柄
		(PROCESSINFOCLASS)0x1F, 	// 查询信息类型
		&bProcessDebugFlag, 		// 输出查询信息
		sizeof(bProcessDebugFlag), 	// 查询类型大小
		NULL); 				// 实际返回大小
	return bProcessDebugFlag ? false : true;
}
