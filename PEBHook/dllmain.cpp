// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#pragma comment(lib,"ntdll.lib")
#include <windows.h>
#include <winternl.h>

unsigned char Oldfunc[5] = {};
unsigned char Newfunc[5] = {0xE9};
LPVOID g_Nt;

HANDLE g_hmutex;

void OnHook();
void UnHook();

NTSTATUS NTAPI MyNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength 
)
{
	switch((DWORD)ProcessInformationClass)
	{
	case 7:
		ProcessInformation = 0;
		return 0;

	case 0x1E :
		ProcessInformation = 0;
		return 0;

	case 0x1F:
		*(DWORD*)ProcessInformation = 1;
		return 0;

	}
	//MessageBox(0, L"haha", L"0", 0);
	WaitForSingleObject(g_hmutex, -1);
	//卸载钩子
	UnHook();
	//调用原函数地址
	NTSTATUS nRet = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
		ProcessInformation, ProcessInformationLength, ReturnLength);
	//挂上钩子
	OnHook();
	ReleaseMutex(g_hmutex);
	return nRet;


}



void OnHook()
{

	DWORD dwOld;
	VirtualProtect(g_Nt, 5, PAGE_EXECUTE_READWRITE, &dwOld);

	//保存修改前的5个字节
	memcpy(Oldfunc, g_Nt, 5);
	//计算偏移量
	DWORD dwOffset = (DWORD)MyNtQueryInformationProcess -
		(DWORD)g_Nt - 5;
	//构造跳转指令
	memcpy(Newfunc + 1, &dwOffset, 4);
	//写入构造跳转（HOOK）
	//修改写入地址属性（代码段没有可写属性）
	
	//修改指令
	memcpy(g_Nt, Newfunc, 5);

	//恢复原来属性
	VirtualProtect(g_Nt, 5, dwOld, &dwOld);
}

void UnHook()
{


	DWORD dwOld;
	VirtualProtect(g_Nt, 5, PAGE_EXECUTE_READWRITE, &dwOld);
	//修改指令
	memcpy(g_Nt, Oldfunc, 5);

	//恢复原来属性
	VirtualProtect(g_Nt, 5, dwOld, &dwOld);

	//
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        //加载DLL
    case DLL_PROCESS_ATTACH:
		g_Nt  = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");

		g_hmutex =  CreateMutex(NULL, FALSE,NULL);

		OnHook();

		break;

	case DLL_THREAD_ATTACH:break;
	case DLL_THREAD_DETACH:break;
    case DLL_PROCESS_DETACH:
		UnHook();
		CloseHandle(g_hmutex);
        break;
    }
    return TRUE;
}

