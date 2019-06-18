
#include <windows.h>
#include <TlHelp32.h>
#include <locale.h>
#include <stdio.h>

bool GetModuleList(DWORD dwPId) {
	HANDLE        hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	// 1. 创建一个模块相关的快照句柄
	hModuleSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,  // 指定快照的类型
		dwPId);            // 指定进程
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return false;
	// 2. 通过模块快照句柄获取第一个模块信息
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return false;
	}
	// 3. 循环获取模块信息
	do {
		wprintf(L"模块基址:%08X,模块大小：%08X,模块名称:%s\n",
			me32.modBaseAddr, me32.modBaseSize, me32.szModule);
	} while (Module32Next(hModuleSnap, &me32));
	// 4. 关闭句柄并退出函数
	CloseHandle(hModuleSnap);
	return true;
}

int main()
{
	setlocale(LC_ALL, "chs");
	DWORD dwId = 0;
	printf("请输入一个ID：");
	scanf_s("%ud", &dwId);
	GetModuleList(dwId);
	return 0;
}