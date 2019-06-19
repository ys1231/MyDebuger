#include "Debug.h"
#include <ShlObj_core.h>
#include <cstdio>
#include "debugRegisters.h"
#include <iostream>
#include<atlstr.h>

#include <DbgHelp.h>

//1. 导入头文件
#include "XEDParse/XEDParse.h"

#ifdef _WIN64
#pragma comment (lib,"XEDParse/x64/XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse/x86/XEDParse_x86.lib")
#endif // _WIN64

#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include"BeaEngine_4.1/Win32/headers/BeaEngine.h"
#include <TlHelp32.h>
#include <winternl.h>
#pragma comment(lib,"BeaEngine_4.1/Win32/Lib/BeaEngine.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"dbghelp.dll")

//初始化 静态成员变量
MyContext Debug::m_Myct = {};
char Debug::m_str[10] = {};

//翻译错误信息
char* GetError()
{
	// 接收错误代码字符串的缓冲区
	static char error[1024];
	LPSTR lpErrorString;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), // 错误代码
		0, (LPSTR)& lpErrorString,
		0, NULL);

	strcpy_s(error, lpErrorString);
	LocalFree(lpErrorString);  // 释放内存
	return error;
}

//输出错误信息
#define PutsError(error) \
			printf("文件名:%s\n函数名:%s\n行号:%d\n错误: %s\n%s\n", \
			__FILE__,	\
			__FUNCTION__, \
			__LINE__, \
			error,	\
			GetError());


Debug::Debug()
{
	PrintIcon();
	PromotionDebugPrivilege(TRUE);
}

Debug::~Debug()
{
}

void Debug::PrintIcon()
{
	// 1. 获得本进程的令牌
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return;
	// 2. 获取提升类型
	TOKEN_ELEVATION_TYPE ElevationType = TokenElevationTypeDefault;
	BOOL                 bIsAdmin = false;
	DWORD                dwSize = 0;
	if (GetTokenInformation(hToken, TokenElevationType, &ElevationType,
		sizeof(TOKEN_ELEVATION_TYPE), &dwSize)) {
		// 2.1 创建管理员组的对应SID
		BYTE adminSID[SECURITY_MAX_SID_SIZE];
		dwSize = sizeof(adminSID);
		CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &dwSize);
		// 2.2 判断当前进程运行用户角色是否为管理员
		if (ElevationType == TokenElevationTypeLimited) {
			// a. 获取连接令牌的句柄
			HANDLE hUnfilteredToken = NULL;
			GetTokenInformation(hToken, TokenLinkedToken, (PVOID)& hUnfilteredToken,
				sizeof(HANDLE), &dwSize);
			// b. 检查这个原始的令牌是否包含管理员的SID
			if (!CheckTokenMembership(hUnfilteredToken, &adminSID, &bIsAdmin))
				return;
			CloseHandle(hUnfilteredToken);
		}
		else {
			bIsAdmin = IsUserAnAdmin();
		}
		CloseHandle(hToken);
	}

	// 3. 判断具体的权限状况
	BOOL bFullToken = false;
	switch (ElevationType) {
	case TokenElevationTypeDefault: /* 默认的用户或UAC被禁用 */
		if (IsUserAnAdmin())  bFullToken = true; // 默认用户有管理员权限
		else                  bFullToken = false;// 默认用户不是管理员组
		break;
	case TokenElevationTypeFull:    /* 已经成功提高进程权限 */
		if (IsUserAnAdmin())  bFullToken = true; //当前以管理员权限运行
		else                  bFullToken = false;//当前未以管理员权限运行
		break;
	case TokenElevationTypeLimited: /* 进程在以有限的权限运行 */
		if (bIsAdmin)  bFullToken = false;//用户有管理员权限，但进程权限有限
		else           bFullToken = false;//用户不是管理员组，且进程权限有限
	}
	// 4. 根据权限的不同控制按钮的显示
	if (!bFullToken) {
		MessageBoxW(0, L"Un Admin", L"提示", 0);

		// 2. 获取当前程序路径
		char szApplication[MAX_PATH] = { 0 };
		DWORD cchLength = _countof(szApplication);
		QueryFullProcessImageName(GetCurrentProcess(), 0, szApplication, &cchLength);
		// 3. 以管理员权限重新打开进程
		SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
		sei.lpVerb = "runas";      // 请求提升权限
		sei.lpFile = szApplication; // 可执行文件路径
		sei.lpParameters = NULL;          // 不需要参数
		sei.nShow = SW_SHOWNORMAL; // 正常显示窗口
		if (ShellExecuteEx(&sei))
			exit(0);
		else
			MessageBoxW(0, L"??????", L"提示", 0);
	}
	//else
		//MessageBoxW(0, L"Admin", L"提示", 0);

}

BOOL Debug::PromotionDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;    HANDLE hToken;
	// 以修改权限的方式，打开进程的令牌
	if (OpenProcessToken(GetCurrentProcess(), 0,
		&hToken)) {
		// 令牌权限结构体
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		//获得LUID
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL); //修改权限
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

BOOL Debug::Open(char FilePath[])
{
	//说明是以创建进程的方式打开的
	IsOpera = TRUE;

	//接收创建进程的信息
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = { 0 };

	//以调试方式创建一个进程
	BOOL ret = CreateProcess(FilePath,NULL,NULL,NULL,FALSE,
		DEBUG_ONLY_THIS_PROCESS| CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);

	//创建失败返回假
	if(!ret)
	{
		MessageBox(0, "创建进程失败!", "错误提示", 0);
		return FALSE;
	}
	m_hProcess = pi.hProcess;

	return TRUE;
}

BOOL Debug::Open(DWORD Pid)
{
	//保存Pid给 注入使用
	m_iard = Pid;

	IsOpera = FALSE;
	return DebugActiveProcess(Pid);
}

VOID Debug::WaitForEvent()
{

	//循环接收异常信息
	while(true)
	{
		
		//等待调试事件
		WaitForDebugEvent(&m_dbgEvent, INFINITE);

		//打开线程进程句柄 获取和修改 信息
		m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dbgEvent.dwProcessId);
		m_hThre = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dbgEvent.dwThreadId);

		switch(m_dbgEvent.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT:
			{
					//printf("异常事件:\n");

					//调用过滤函数
					FilterException();
		
					break;
				}
			case CREATE_THREAD_DEBUG_EVENT:
				printf("线程创建\n");
				break;
			case CREATE_PROCESS_DEBUG_EVENT:
				printf("进程创建\n");
				//DLL注入
				DllInject();

				//初始化符号
				SymInitialize(m_hProcess, NULL, FALSE);

				DWORD g_ImageBase = (DWORD)m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage;//保存镜像基址
				//DWORD g_OEP = (DWORD)m_dbgEvent.u.CreateProcessInfo.lpStartAddress;///保存程序OEP
				//加载主程序模块符号信息
				DWORD64 moduleAddress = SymLoadModule64(m_hProcess,m_dbgEvent.u.CreateProcessInfo.hFile, NULL, NULL, g_ImageBase, 0);
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				printf("线程退出\n");
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				{
					printf("进程退出\n");

						//如果检测到进程退出 那么我们就结束程序
					goto EfNOP;
				}
			case LOAD_DLL_DEBUG_EVENT:
				printf("DLL加载\n");
				SymLoadModule64(m_hProcess, m_dbgEvent.u.LoadDll.hFile, NULL, NULL, (DWORD64)m_dbgEvent.u.LoadDll.lpBaseOfDll, 0);
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				printf("DLL卸载\n");
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				printf("调试信息\n");
				break;
		}
		
		//回复调试子系统 
		//DBG_CONTINUE
		//DBG_EXCEPTION_NOT_HANDLED
		ContinueDebugEvent(m_dbgEvent.dwProcessId, m_dbgEvent.dwThreadId, m_ReplyInfo);

	
		//关闭打开的线程进程句柄
		CloseHandle(m_hProc);

		CloseHandle(m_hThre);




	}
	EfNOP:
	return;
}

VOID Debug::FilterException()
{
	//从调试异常信息中获取到异常信息
	m_ExcepInfo = m_dbgEvent.u.Exception.ExceptionRecord;

	//临时变量 根据内存异常 
	//断点是否需要设置内存页为异常 
	//为下一次做准备 默认不需要设置
	//bool IsMemException = false;

	switch(m_ExcepInfo.ExceptionCode)
	{
		//软件断点 int3 //程序会自己断下来一次
	case EXCEPTION_BREAKPOINT:

		//判断是否是系统断点
		if(IssystemBp)
		{
			IssystemBp = false;
			printf("到达系统断点:%08X\n",(DWORD)m_ExcepInfo.ExceptionAddress);

			//隐藏peb
			PROCESS_BASIC_INFORMATION peb;

			DWORD dw;
			NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &peb, sizeof(peb), &dw);

			DWORD pISdbg = ((DWORD)peb.PebBaseAddress + 0x2);
			WriteProcessMemory(m_hProcess, (LPVOID)pISdbg, "\x0", 2, &dw);
			
			//显示帮助命令
			GetHelp();

			//加载插件
			LoadPlugin();

		}else
		{
			//确认是否是我们自己下的断点 
			//恢复原来的属性
			ReparBreak();
		}

		break;

		//硬件断点 4个 单步异常
	case EXCEPTION_SINGLE_STEP:
	{
		IsInputAndShowAsm = TRUE;

		if (!IsTF) {

			IsHPBreak = FALSE;

			for (auto& i : m_BreakPointAll) {
				if ((DWORD)m_ExcepInfo.ExceptionAddress == i.Address && i.BreakType == HdFlag) {

					//如果异常地址相同说明需要修复
					ReparBreakHD();

				}
				else
					IsHPBreak = TRUE;
			}
			//再次下所有断点
			if (IsRepar && IsHPBreak) {
				ReparSetBreak();
				IsInputAndShowAsm = FALSE;
				IsRepar = FALSE;
			}
		}
		else
			IsTF = FALSE;
		if (IsRepar && IsHPBreak) {
			ReparSetBreak();
			IsInputAndShowAsm = TRUE;
			IsRepar = FALSE;
		}
		break;
	}
		//访问没有权限的虚拟地址 内存断点
	case EXCEPTION_ACCESS_VIOLATION:

		ReparMemBreak();

		break;
	default:
		m_ReplyInfo = DBG_EXCEPTION_NOT_HANDLED;
		break;
	}

	if (IsInputAndShowAsm) {
		//显示反汇编
		ShowAsm();

		//等待用户输入
		GetCommand();
	}

	return ;      
}

VOID Debug::ShowAsm()
{
	//显示寄存器信息
	CONTEXT ct = {};

	//获取全部寄存器信息
	ct.ContextFlags = CONTEXT_ALL;

	PEFLAGS PEflags = (PEFLAGS)&ct.EFlags;

	GetThreadContext(m_hThre, &ct);

	//输出到显示屏上
	printf("-----------------------寄存器-------------------------");						printf("-----------------EFlags-----------------------\n");
	printf("|Eax:%08X Ecx:%08X Edx:%08X Ebx:%08X|\t", ct.Eax, ct.Ecx, ct.Edx, ct.Ebx);		printf("ZF %d  PF %d  AF %d  OF %d  SF %d\n",PEflags->ZF,PEflags->PF,PEflags->AF,PEflags->OF,PEflags->SF);
	printf("|Esp:%08X Ebp:%08X Esi:%08X Edi:%08X|\t", ct.Esp, ct.Ebp, ct.Esi, ct.Edi);		printf("DF %d  CF %d  TF %d  IF %d  \n",PEflags->DF,PEflags->CF,PEflags->TF,PEflags->IF);
	printf("             |EIP:");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xC);
	printf("%08X\n\n", ct.Eip);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x7);

	//显示返汇编信息
	char buff[10 * 15] = {};
	SIZE_T ret = 0;

	//读取内存中的机器码
	if(!ReadProcessMemory(m_hProc, (LPVOID)m_ExcepInfo.ExceptionAddress,buff,sizeof(buff),&ret))
	{
		PutsError("读取进程内存失败");
		return;
	}

	//使用反汇编引擎输出反汇编信息
	DISASM disasm = {};
	
	//设置要进行反汇编的Opcode的内存地址
	disasm.EIP = (UIntPtr)buff;

	//设置当前指令所在地址
	disasm.VirtualAddr = (UInt64)m_ExcepInfo.ExceptionAddress;	//异常地址

	//设置按照32位汇编机器码进行反汇编
	disasm.Archi = 0;

	int nCount = 0;

	//默认字体颜色是白色
	WORD l_color = 0x7;
	while (nCount <= 10)
	{
		int nLen = Disasm(&disasm);

		if (nLen == -1) {
			break;
		}

		printf("%08llX | ",disasm.VirtualAddr);

		for (int i = 0; i < nLen; ++i) {
			printf("%02X", (DWORD) * (BYTE*)(disasm.EIP + i));
		}
		printf("%*c", 18 - nLen * 2, ' ');

		//不同的命令不同的颜色
		if (!strncmp("push", disasm.CompleteInstr, 4))
			l_color = 0x1;
		else if (!strncmp("e", disasm.CompleteInstr, 1))
			l_color = 0xA;
		else if (!strncmp("call", disasm.CompleteInstr,4))
			l_color = 0x9;
		else if (!strncmp("ret", disasm.CompleteInstr,3))
			l_color = 0x9;
		else if (!strncmp("j", disasm.CompleteInstr,1))
			l_color = 0xC;
		else if (!strncmp("pop", disasm.CompleteInstr, 3))
			l_color = 0x1;
		else
			l_color = 0x7;

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), l_color);
		printf(" | %s\n", disasm.CompleteInstr);

		//恢复原来的白色
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x7);

		disasm.EIP += nLen;
		disasm.VirtualAddr += nLen;
		++nCount;
	}


	return ;
}

VOID Debug::ShowAsm(DWORD c_Address, DWORD c_Len)
{
	

	//显示返汇编信息
	char buff[100 * 15] = {};
	SIZE_T ret = 0;

	if (c_Len > 100)
		return;

	//读取内存中的机器码
	if (!ReadProcessMemory(m_hProc, (LPVOID)c_Address, buff, sizeof(buff), &ret))
	{
		PutsError("读取进程内存失败");
		return;
	}

	//使用反汇编引擎输出反汇编信息
	DISASM disasm = {};

	//设置要进行反汇编的Opcode的内存地址
	disasm.EIP = (UIntPtr)buff;

	//设置当前指令所在地址
	disasm.VirtualAddr = (UInt64)c_Address;	//异常地址

	//设置按照32位汇编机器码进行反汇编
	disasm.Archi = 0;

	int nCount = 0;

	//默认字体颜色是白色
	WORD l_color = 0x7;
	while (nCount <= c_Len)
	{
		int nLen = Disasm(&disasm);
		if (nLen == -1) {
			break;
		}

		printf("%08llX | ", disasm.VirtualAddr);

		for (int i = 0; i < nLen; ++i) {
			printf("%02X", (DWORD) * (BYTE*)(disasm.EIP + i));
		}
		printf("%*c", 18 - nLen * 2, ' ');

		//不同的命令不同的颜色
		if (!strncmp("push", disasm.CompleteInstr, 4))
			l_color = 0x1;
		else if (!strncmp("e", disasm.CompleteInstr, 1))
			l_color = 0xA;
		else if (!strncmp("call", disasm.CompleteInstr, 4))
			l_color = 0x9;
		else if (!strncmp("ret", disasm.CompleteInstr, 3))
			l_color = 0x9;
		else if (!strncmp("j", disasm.CompleteInstr, 1))
			l_color = 0xE;
		else if (!strncmp("pop", disasm.CompleteInstr, 3))
			l_color = 0x1;
		else
			l_color = 0x7;

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), l_color);
		printf(" | %s\n", disasm.CompleteInstr);

		//恢复原来的白色
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x7);

		disasm.EIP += nLen;
		disasm.VirtualAddr += nLen;
		++nCount;
	}

	return ;
}

VOID Debug::GetCommand()
{
	//获取用户输入缓冲区
	char cmd[40]={};
	printf(">");

	DWORD Address = 0;
	char str[3] = {};
	DWORD c_Type = 0;
	DWORD c_Len = 0;

	while(true)
	{
		scanf("%s",cmd);

		if(!_stricmp("t", cmd))			//单步执行断点
		{
			SetBreakTF();
			IsTF = TRUE;
			break;
		}else if(!_stricmp("tg",cmd))
		{
			if(!SetStepTF())
			{
				printf("单步失败 !");
			}
			else
				break;
		}
		else if (!_stricmp("g", cmd)) {
			
			break;
		}
		else if (!_stricmp("cls", cmd))
		{
			system("cls");
			ShowAsm();
		}else if(!_stricmp("fasm", cmd))
		{
			scanf("%X %d", &Address, &c_Len);
			ShowAsm(Address, c_Len);
		}
		else if (!_stricmp("bp", cmd))	//软件断点  
		{
			scanf("%X",&Address);		//接收用户输入地址

			SetBreakInt3(Address);		//传入函数开始下软件断点
		}
		else if(!_stricmp("hp", cmd))	//硬件断点
		{
			
			scanf("%X%s", &Address, str);

			// 根据用户输入设置断点类型  printf("1字节:0|2字节:1|4字节:3");
			if (!_stricmp(str, "-x")) {
				c_Type = 0; c_Len = 0;
			}else if(!_stricmp(str, "-r"))
			{
				c_Type = 1; 
				scanf("%d", &c_Len);
			}
			else if (!_stricmp(str, "-w"))
			{
				c_Type = 3; 
				scanf("%d", &c_Len);
			}
			else {
				printf("Input Error\n");
				printf(">");
				continue;
			}
			SetBreakHD(Address,c_Type,c_Len);
		}
		else if (!_stricmp("np", cmd))	//下内存断点
		{
			scanf("%X%s", &Address, str);
			SetMemBreak(Address,str);
		}
		else if(!_stricmp("bpt",cmd))
		{
			scanf("%X", &Address);
			SetBreakInt3(Address, true, true);
		}
		else if(!_stricmp("fp", cmd))	//查看所有断点
		{
			//查看所有断点
			FindBreak();
		}
		else if(!_stricmp("dp",cmd))	//删除断点
		{
			scanf("%X",&Address);
			ClearBreak(Address);

		}
		else if(!_stricmp("xasm",cmd))	//修改汇编
		{
			AlterAsm();
		}else if(!_stricmp("fm",cmd))	//查看内存
		{
			scanf("%X", &Address);
			ShowMem(Address);
		}
		else if (!_stricmp("xm", cmd))  //修改内存
		{
			scanf("%X", &Address);
			AlterMem(Address);
			ShowAsm();
		}else if(!_stricmp("fz",cmd))  //查看内存
		{
			scanf("%d", &c_Len);
			ShowStack(c_Len);
		}else if(!_stricmp("xr",cmd))  //修改寄存器
		{
			AlterRegister();
			ShowAsm();
		}else if(!_stricmp("fmd",cmd))	//查看模块
		{
			GetModuleList();
		}else if(!_stricmp("h",cmd))	//查看帮助
		{
			GetHelp();
		}else if(!_stricmp("fpe",cmd))  //查看PE信息
		{
			GetModuleList();
			scanf("%X %X", &Address, &c_Len);
			Analysis_Export_Import(Address,c_Len);
		}else if(!_stricmp("plugin",cmd))
		{
			FUN func = (FUN)m_FunAddress;
			func();
		}
		else
			printf("Input Error\n");

		printf(">");
		
		
	}


	return;
}

VOID Debug::GetHelp()
{
	printf("t:   单步步入\n");
	printf("tg:  单步步过\n");
	printf("g:   继续执行\n");
	printf("cls: 清屏\n");
	printf("fasm:地址 查看指定地址汇编信息\n");
	printf("bp:   软件断点|| 条件断点 (1) \n");
	printf("hp:   -x|-r n |-w n 执行 读|写\n");
	printf("np:   -x|-r |-w  内存断点\n");
	printf("fp:  查看所有断点\n");
	printf("dp:  地址 删除指定断点和查看配合使用\n");
	printf("xasm:修改汇编代码\n");
	printf("fm:  地址 查看内存数据(默认16个字节)\n");
	printf("xm:  地址 修改内存数据\n");
	printf("fz:  (n)查看栈\n");
	printf("xr:  修改寄存器\n");
	printf("fmd: 查看模块信息\n");
	printf("fpe: 地址 大小 查看PE信息\n");
	printf("plugin: 使用插件");
	return ;
}

VOID Debug::FindBreak()
{
	//输出所有断点信息Local(0)/global(1)


	char pType[20] = {};

	printf("-------共有{%d}个断点-------\n", m_BreakPointAll.size());

	//遍历断点动态数组
	for (auto& i : m_BreakPointAll) {

		switch(i.BreakType)
		{
		case 0:strcpy(pType, "软件断点");
			break;
		case 1:strcpy(pType, "硬件断点");
			break;
		case 2:strcpy(pType, "内存断点");
			break;
		}

		printf("|Address:%08X|%d|Type:%s\n", i.Address,i.Execute,pType);
	}
	return ;
}

VOID Debug::AlterMem(DWORD c_Address)
{
	//临时变量
	SIZE_T size = {};
	DWORD Oldproperty = {};

	DWORD str = {};

	//BYTE* l_Mem;
	//修改调试进程内存属性 
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, PAGE_READWRITE, &Oldproperty)) {
		PutsError("设置内存分页属性失败");
		return;
	}

	printf(":");
	scanf("%X",&str);

	//写
	if (!WriteProcessMemory(m_hProc, (LPVOID)c_Address, &str, 1, &size)) {
		PutsError("修改内存数据失败");

		//把原来的内存属性还原回去
		VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, Oldproperty, &Oldproperty);

		return ;
	}

	
	//把原来的内存属性还原回去
	VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, Oldproperty, &Oldproperty);

	return;
}

VOID Debug::ShowStack(const DWORD Size)
{
	DWORD size;

	DWORD l_stack[100] = {};

	//显示寄存器信息
	CONTEXT ct = { CONTEXT_CONTROL };

	//获取当前线程上下文
	GetThreadContext(m_hThre, &ct);

	DWORD *EspAddres = (DWORD*)ct.Esp;

	if (Size > 100)
		return;
	for (int i = 0; i < Size; i++) {

		ReadProcessMemory(m_hProc, EspAddres,& (l_stack[i]),4, &size);

	printf("%08X:%08X\t", EspAddres, l_stack[i]);

	if (!((i + 1) % 2))
		printf("\n");

	EspAddres++;
	}
	printf("\n");


	return ;
}

VOID Debug::AlterRegister()
{
	CONTEXT ct = { CONTEXT_ALL };
	GetThreadContext(m_hThre, &ct);

	//接收用户输入的寄存器
	char str[10] = {};
	DWORD l_dword = 0;

	printf("Input Addres|n\n:");
	aaa:
	scanf("%s%d", str,&l_dword);

	if (!_stricmp("Eip", str))
		ct.Eip = l_dword;
	else if (!_stricmp("Eax", str))
		ct.Eax = l_dword;
	else if (!_stricmp("Ecx", str))
		ct.Ecx = l_dword;
	else if (!_stricmp("Edx", str))
		ct.Edx = l_dword;
	else if (!_stricmp("Ebx", str))
		ct.Ebx = l_dword;
	else if (!_stricmp("Esi", str))
		ct.Esi = l_dword;
	else if (!_stricmp("Edi", str))
		ct.Edi = l_dword;
	else if (!_stricmp("Esp", str))
		ct.Esp = l_dword;
	else if (!_stricmp("Ebp", str))
		ct.Ebp = l_dword;
	else {
		printf("没有找到请重新输入\n:");
		goto aaa;
	}

	if(!SetThreadContext(m_hThre, &ct))
	{
		PutsError("修改寄存器出错");
		return;
	}

	printf("修改完成");
	return ;
}

VOID Debug::GetModuleList()
{
	setlocale(LC_ALL, "chs");

	HANDLE        hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	// 1. 创建一个模块相关的快照句柄
	hModuleSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,  // 指定快照的类型
		m_dbgEvent.dwProcessId);            // 指定进程
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return ;

	// 通过模块快照句柄获取第一个模块信息
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return;
	}
	// 循环获取模块信息
	do {
		wprintf(L"模块名称:%S \t 模块基址:%08X\t 模块大小：%08X\n",
			me32.szModule,me32.modBaseAddr, me32.modBaseSize);
	} while (Module32Next(hModuleSnap, &me32));

	// 关闭句柄并退出函数
	CloseHandle(hModuleSnap);

	return ;
}

BOOL Debug::DllInject()
{

	HANDLE hProcess = NULL;

	//判断是以什么方式打开的句柄
	if (IsOpera) {
		hProcess = m_hProcess;
	}
	else {
		//1.打开进程
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_iard);
		m_hProcess = hProcess;
	}
	//2.在目标进程中申请空间
	LPVOID pAddr = VirtualAllocEx(hProcess, NULL, 200, MEM_COMMIT, PAGE_READWRITE);

	//3.在目标进程中写入dll路径
	CHAR dllPath[] = "test.dll";
	SIZE_T dwSzie = 0;
	WriteProcessMemory(hProcess, pAddr, dllPath, sizeof(dllPath), &dwSzie);

	//4.创建远程线程，注入dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		pAddr,
		NULL, NULL);

	//5.关闭句柄，释放空间
	//WaitForSingleObject(hThread, -1);
	CloseHandle(hThread);

	return 0;
}

VOID Debug::Analysis_Export_Import(DWORD c_Address, DWORD c_BaseSize)
{
	//申请堆空间
	m_pFile = new char[c_BaseSize]{};
	SIZE_T dwdize=0;
	DWORD dwold=0;

	if(!VirtualProtectEx(m_hProcess,(LPVOID)c_Address, c_BaseSize,PAGE_EXECUTE_READWRITE,&dwold))
	{
		PutsError("修改内存属性出错")
	}

	if(!ReadProcessMemory(m_hProcess, (LPVOID)c_Address, m_pFile, c_BaseSize,&dwdize))
	{
		PutsError("读取内存出错");
	}

	if(!VirtualProtectEx(m_hProcess, (LPVOID)c_Address, c_BaseSize, dwold, &dwold))
	{
		PutsError("修改内存属性出错")
	}


	m_pDos = (PIMAGE_DOS_HEADER)m_pFile;
	m_pNT = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pFile);


	printf("导出表\n");

	//1.获取数据目录表第一个字段 得到导出表RVA
	DWORD ExportDir = m_pNT->OptionalHeader.DataDirectory[0].VirtualAddress;

	if (!ExportDir)
	{
		printf("没有导入表!");
		return;
	}

	//2.获取导出表文件位置
	PIMAGE_EXPORT_DIRECTORY l_pExport = (PIMAGE_EXPORT_DIRECTORY)(ExportDir+m_pFile);

	//3.获取PE文件名称
	printf("%s\n", (char*)(l_pExport->Name + m_pFile));

	//4.获取序号基数
	printf("序号基数:%08x\n", l_pExport->Base);

	//5.遍历输出所有导出函数

	//5.1导出函数总个数
	DWORD FunLen = l_pExport->NumberOfFunctions;

	//5.2导出函数名称个数
	DWORD NameFunLen = l_pExport->NumberOfNames;

	//6.获取三个函数地址表地址
	PDWORD pFunAddress = (PDWORD)(l_pExport->AddressOfFunctions + m_pFile);
	PDWORD pFunName = (PDWORD)(l_pExport->AddressOfNames + m_pFile);
	PWORD  pOrdinals = (PWORD)(l_pExport->AddressOfNameOrdinals + m_pFile);

	//遍历输出所有导出函数

	for (int i = 0; i < FunLen; i++)
	{
		//如果函数地址为0 说明函数地址无效 寻找下一个
		if (pFunAddress[i] == 0)
			continue;

		printf("函数序号:%d\t", i + l_pExport->Base);

		bool Flag = false;
		for (int j = 0; j < NameFunLen; j++)
		{
			if (pOrdinals[j] == i)
			{
				printf("函数名称:%s\t", (char*)(pFunName[j] + m_pFile));
				Flag = true;
			}

		}
		if (!Flag)
			printf("函数名称:没有\t");

		printf("函数地址:%08x\n",(pFunAddress[i] + m_pFile));

	}

	printf("导入表\n");
	//1.获取数据目录表第二个字段 得到导入表RVA
	DWORD ImportDir = m_pNT->OptionalHeader.DataDirectory[1].VirtualAddress;

	if(!ImportDir)
	{
		printf("没有导入表!");
		return ;
	}

	//2.获取导入表文件位置
	PIMAGE_IMPORT_DESCRIPTOR l_pImport = (PIMAGE_IMPORT_DESCRIPTOR)(ImportDir + m_pFile);

	//遍历导入表和 里面的函数
	while (l_pImport->Name)
	{
		//打印模块名
		printf("\n\t\t模块名称:%s\n", (char*)(l_pImport->Name + m_pFile));

		//遍历导入函数
		PIMAGE_THUNK_DATA l_pThunk = (PIMAGE_THUNK_DATA)(l_pImport->OriginalFirstThunk + m_pFile);

		while (l_pThunk->u1.AddressOfData)
		{
			//判断导入方式   (最高位是否为1 )1 是序号导入 0是函数名导入
			if (IMAGE_SNAP_BY_ORDINAL(l_pThunk->u1.AddressOfData))
			{
				//序号是 l_pThunk->ul.Ordinal 
				printf("\t导入函数名称:[NULL]\t导入函数序号:%d\n", l_pThunk->u1.Ordinal && 0xFFFF);
			}
			else
			{
				//名称导入 
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(l_pThunk->u1.AddressOfData + m_pFile);

				printf("\t导入函数名称:[%s]\t导入函数序号:%d\n", pName->Name, pName->Hint);
			}

			//下一个函数
			l_pThunk++;
		}

		//下一个导入结构
		l_pImport++;
	}


	delete[] m_pFile;
	m_pFile = nullptr;

	return ;
}

VOID Debug::LoadPlugin()
{
	
	m_FunAddress =GetProcAddress(LoadLibraryA("Plugin/MainPlugin.dll"), "MainPlugin");

	return ;
}

VOID Debug::ShowMem(DWORD c_Address)
{
	//临时变量
	SIZE_T size = {};
	DWORD Oldproperty = {};

	unsigned char l_Mem[16] = {};
	//BYTE* l_Mem;
	//修改调试进程内存属性 
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, PAGE_READWRITE, &Oldproperty)) {
		PutsError("设置内存分页属性失败");
		return ;
	}

	//读取第16个字节 保存起来
	if (!ReadProcessMemory(m_hProc, (LPVOID)c_Address, &l_Mem, 16, &size)) {
		PutsError("读取进程内存失败");
		return ;
	}
	printf("%08X:\n", c_Address);
	//单个字节输出信息
	for(int i=0;i<16;i++)
	{
		printf("[%02d]%02X ",i, l_Mem[i]);
		
		if ((i+1)%8==0)
			printf("\n");
	}
	printf("\n");
	printf("%S\t%s\n", l_Mem,l_Mem);
	//把原来的内存属性还原回去
	VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, Oldproperty, &Oldproperty);


	return ;
}

VOID Debug::AlterAsm()
{
	printf("请输入需要修改汇编的地址\n:");
	//汇编类对象
	XEDPARSE xed = { 0 };

	// 接受生成opcode的的初始地址
	scanf_s("%llx", &xed.cip);

	getchar();

	DWORD OldPage = 0;
	DWORD ret = 0;

	do
	{
		aaa:
		// 接收指令
		printf("指令：");
		gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

		if (!strcmp(xed.instr,"exit"))
			break;

		// xed.cip, 汇编带有跳转偏移的指令时,需要配置这个字段
		if (XEDPARSE_OK != XEDParseAssemble(&xed))
		{
			printf("指令错误：%s\n", xed.error);
			goto aaa;
		}

		// 打印汇编指令所生成的opcode
		//printf("%08X : ", xed.cip);
		//printOpcode(xed.dest, xed.dest_size);
		//printf("\n");

		if(!VirtualProtectEx(m_hProc, (LPVOID)xed.cip, xed.dest_size, PAGE_READWRITE, &OldPage))
		{
			PutsError("修改内存属性失败");
			return;
		}

		
		if (!WriteProcessMemory(m_hProc, (LPVOID)xed.cip, xed.dest, xed.dest_size, &ret)) {
			PutsError("写入汇编失败");

			//把原来的内存属性还原回去
			VirtualProtectEx(m_hProc, (LPVOID)xed.cip, xed.dest_size, OldPage, &OldPage);

			return;
		}

		//把原来的内存属性还原回去
		VirtualProtectEx(m_hProc, (LPVOID)xed.cip, xed.dest_size, OldPage, &OldPage);



		// 将地址增加到下一条指令的首地址
		xed.cip += xed.dest_size;
	} while (*xed.instr);

	ShowAsm();

	return ;
}

BOOL Debug::SetBreakTF()
{
	//获取线程上下文并设置TF 标志位
	CONTEXT ct = { CONTEXT_CONTROL };

	//获取线程上下文
	if(!GetThreadContext(m_hThre, & ct))
	{
		PutsError("获取线程上下文失败");
		return FALSE;
	}

	//设置TF 单步断点
	EFLAGS* pEflag = (EFLAGS*)& ct.EFlags;
	pEflag->TF = 1;

	//设置回去
	if (!SetThreadContext(m_hThre, &ct)) {
		PutsError("设置线程上下文失败");
		return FALSE;
	}

	return TRUE;
}

BOOL Debug::SetStepTF()
{

	BreakPoint bp;

	//显示返汇编信息
	char buff[1 * 15] = {};
	SIZE_T ret = 0;

	//读取内存中的机器码
	if (!ReadProcessMemory(m_hProc, (LPVOID)m_ExcepInfo.ExceptionAddress, buff, sizeof(buff), &ret))
	{
		PutsError("读取进程内存失败");
		return FALSE;
	}

	//使用反汇编引擎输出反汇编信息
	DISASM disasm = {};

	//设置要进行反汇编的Opcode的内存地址
	disasm.EIP = (UIntPtr)buff;

	//设置当前指令所在地址
	disasm.VirtualAddr = (UInt64)m_ExcepInfo.ExceptionAddress;	//异常地址

	//设置按照32位汇编机器码进行反汇编
	disasm.Archi = 0;

	


	int nLen = Disasm(&disasm);
	if (nLen == -1) {
		return FALSE;
	}

	//过滤call

	if (!strncmp("call", disasm.CompleteInstr, 4)|| !strncmp("rep", disasm.CompleteInstr, 3)) {
	
		//是call
		SetBreakInt3(disasm.VirtualAddr + nLen, false);
	}
	else {
		//不是call 说明不需要步过 直接单步执行
		SetBreakTF();

		//说明是我们自己下的TF 硬件断点
		IsTF = TRUE;
	}
	//disasm.EIP + nLen;
	//disasm.VirtualAddr + nLen;
	
	//成功返回真
	return TRUE;
}

BOOL Debug::SetBreakInt3(DWORD c_Address,bool c_Execute, bool c_CondiTion)
{

	for(auto&i:m_BreakPointAll)
	{
		if(i.Address==c_Address)
		{
			i.Execute = TRUE;
			return TRUE;
		}
	}

	//判断一下这是不是一个条件断点 如果是条件断点就应该
	if(c_CondiTion)
	{
		printf("请选择设置条件:(1.执行次数|2.某个寄存器的值):");

		scanf("%d", &IsConDitionType);

		if (IsConDitionType == 1) {

			printf("请输入最大执行次数\n:");
			scanf("%d", &IsConDiTion);

		}else if(IsConDitionType==2)
		{
			
			//接收用户输入的寄存器
			
			DWORD l_dword = 0;

			printf("Input Addres|n\n:");
		aaa:
			scanf("%s%d", m_str, &l_dword);

			if (!_stricmp("Eax", m_str))
				m_Myct.Eax = l_dword;
			else if (!_stricmp("Ecx", m_str))
				m_Myct.Ecx = l_dword;
			else if (!_stricmp("Edx", m_str))
				m_Myct.Edx = l_dword;
			else if (!_stricmp("Ebx", m_str))
				m_Myct.Ebx = l_dword;
			else if (!_stricmp("Esi", m_str))
				m_Myct.Esi = l_dword;
			else if (!_stricmp("Edi", m_str))
				m_Myct.Edi = l_dword;
			else {
				printf("没有设置这个寄存器\n请重新输入\n:");
				goto aaa;
			}
		}
	}

	//保存断点信息 
	BreakPoint bp ={c_Address,0,CcFlag ,c_Execute,0,c_CondiTion };

	//临时变量
	SIZE_T size = {};
	DWORD old = {};

	//修改调试进程内存属性 
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, PAGE_READWRITE, &old)) {
		PutsError("设置内存分页属性失败");
		return FALSE;
	}

	//读取第一个字节 保存起来
	if (!ReadProcessMemory(m_hProc, (LPVOID)c_Address, &bp.OldData, 1, &size)) {
		PutsError("读取进程内存失败");
		return FALSE;
	}

	//写入CC 下软件断点
	if (!WriteProcessMemory(m_hProc, (LPVOID)c_Address, "\xCC", 1, &size)) {
		PutsError("写入进程内存CC失败");
		
		//把原来的内存属性还原回去
		VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, old, &old);

		return FALSE;
	}

	//把原来的内存属性还原回去
	VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, old, &old);


	m_BreakPointAll.push_back(bp);

	return TRUE;
}

BOOL Debug::ReparBreak()
{
	//循环遍历动态数组
	//看一下是不是自己下的
	//如果是  就还原回去 
	//并且把EIP-1 因为int是陷阱异常 Eip指向下一条

	for(auto&i:m_BreakPointAll)
	{
		if(i.BreakType==CcFlag&&i.Address==(DWORD)m_ExcepInfo.ExceptionAddress)
		{
			//临时变量
			SIZE_T ret = {};
			DWORD old = {};

			//修改调试进程内存属性 
			if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, PAGE_READWRITE, &old)) {
				PutsError("设置内存分页属性失败");
				return FALSE;
			}

			//写入原来的值
			if (!WriteProcessMemory(m_hProc, (LPVOID)i.Address, &i.OldData, 1, &ret)) {
				PutsError("还原int3断点数据失败");
				return FALSE;
			}

			//把原来的内存属性还原回去
			VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, old, &old);

			//EIP-1
			CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_ALL;
			GetThreadContext(m_hThre, &ct);
			ct.Eip--;
			SetThreadContext(m_hThre, &ct);

			//TF 断下来以后需要 再次下断点
			IsRepar = TRUE;
			SetBreakTF();

			static DWORD CondiTionLen = 0;

			

			//如果为真说明这是一个条件断点
			if(i.IsCondition)
			{	
				if (IsConDitionType == 1) {
					//只要断到这个断点  计数器就+1
					CondiTionLen++;

					//如果命中次数与设置的执行次数相同 
					if (CondiTionLen == IsConDiTion)
					{
						//说明 需要接收用户处理
						IsInputAndShowAsm = TRUE;

						//说明 断点目的已经达到 不需要再次下断点
						i.Execute = FALSE;
					}
					else
						IsInputAndShowAsm = FALSE;
				}else if(IsConDitionType==2)
				{

					//获取线程上下文并设置TF 标志位
					CONTEXT ct = { CONTEXT_ALL };

					//获取线程上下文
					if (!GetThreadContext(m_hThre, &ct))
					{
						PutsError("获取线程上下文失败");
						return FALSE;
					}
					bool l_cond=false;
					
					if (!_stricmp("Eax", m_str))
						if (m_Myct.Eax == ct.Eax)
							l_cond = true;
					else if (!_stricmp("Ecx", m_str))
						if(m_Myct.Ecx ==ct.Ecx)
							l_cond = true;
					else if (!_stricmp("Edx", m_str))
						if (m_Myct.Edx == ct.Edx)
							l_cond = true;
					else if (!_stricmp("Ebx", m_str))
						if(m_Myct.Ebx == ct.Ebx)
							l_cond = true;
					else if (!_stricmp("Esi", m_str))
						if (m_Myct.Esi == ct.Esi)
							l_cond = true;
					else if (!_stricmp("Edi", m_str))
						if (m_Myct.Edi == ct.Edi)
							l_cond = true;



					if(l_cond)
					{
						//说明 需要接收用户处理
						IsInputAndShowAsm = TRUE;

						//说明 断点目的已经达到 不需要再次下断点
						i.Execute = FALSE;

						//此时需要初始化 自己的
						m_Myct.Eax = 0;
						m_Myct.Ecx = 0;
						m_Myct.Edx = 0;
						m_Myct.Ebx = 0;
						m_Myct.Esi = 0;
						m_Myct.Edi = 0;

					}
					else
						IsInputAndShowAsm = FALSE;
				}
			}else
				IsInputAndShowAsm = TRUE;

			return TRUE;
		}

		

	}


	return TRUE;
}

BOOL Debug::SetBreakHD(DWORD c_Address, DWORD c_Type, DWORD c_Len)
{
	
	//对断点长度进行处理
	if(c_Len==1)	
	{
		c_Address -= c_Address % 2;
	}else if(c_Len==3)
	{
		c_Address -= c_Address % 4;
	}
	
	// 调试寄存器 Dr0-DR7 

	// 用于保存原来内存的数据
	BreakPoint HdInfo = { c_Address,0,HdFlag,TRUE,0};

	// 获取调试寄存器
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };

	//获取线程上下文
	if (!GetThreadContext(m_hThre, &ct))
	{
		PutsError("获取线程上下文失败");
		return FALSE;
	}

	//获取 Dr7 结构体并解析
	PDR7 Dr7 = (PDR7)& ct.Dr7;

	// 通过 Dr7 中的L(n) 知道当前的调试寄存器是否被使用
	if (Dr7->L0 == FALSE)
	{
		// 设置硬件断点是否有效
		Dr7->L0 = TRUE;

		// 设置断点的类型
		Dr7->RW0 = c_Type;

		// 设置断点地址的对齐长度
		Dr7->LEN0 = c_Len;

		// 设置断点的地址
		ct.Dr0 = (DWORD)c_Address;
	}
	else if (Dr7->L1 == FALSE)
	{
		Dr7->L1 = TRUE;
		Dr7->RW1 = c_Type;
		Dr7->LEN1 = c_Len;
		ct.Dr1 = (DWORD)c_Address;
	}
	else if (Dr7->L2 == FALSE)
	{
		Dr7->L2 = TRUE;
		Dr7->RW2 = c_Type;
		Dr7->LEN2 = c_Len;
		ct.Dr2 = (DWORD)c_Address;
	}
	else if (Dr7->L3 == FALSE)
	{
		Dr7->L3 = TRUE;
		Dr7->RW3 = c_Type;
		Dr7->LEN3 = c_Len;
		ct.Dr3 = (DWORD)c_Address;
	}
	else
	{
		PutsError("硬件断点已经有4个了");
		return false;
	}

	//设置回去
	if (!SetThreadContext(m_hThre, &ct)) {
		PutsError("设置线程上下文失败");
		return FALSE;
	}


	//标记需要修复一次硬件断点
	//IsHPBreak = TRUE;
	m_BreakPointAll.push_back(HdInfo);

	return TRUE;
}

BOOL Debug::ReparBreakHD()
{
	for (auto& i : m_BreakPointAll) {
		// 如果是硬件断点就先设为无效
		if (i.BreakType == HdFlag && i.Address == (DWORD)m_ExcepInfo.ExceptionAddress)
		{
			//打开线程句柄
			//HANDLE l_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,m_hThre);

			// 获取到调试寄存器
			CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
			GetThreadContext(m_hThre, &Context);

			// 获取 Dr7 寄存器
			PDR7 Dr7 = (PDR7)& Context.Dr7;

			//// 根据 Dr6 的低 4 位知道是谁被触发了
			//int index = Context.Dr6 & 0xF;


			// 将触发的断点设置成无效的

			if(Context.Dr0==i.Address)
			{
				Dr7->L0 = 0;
			}else if(Context.Dr1 == i.Address)
			{
				Dr7->L1 = 0;
			}
			else if (Context.Dr2 == i.Address)
			{
				Dr7->L2 = 0;
			}
			else if (Context.Dr3 == i.Address)
			{
				Dr7->L3 = 0;
			}
	
			// 将修改更新到线程
			if (!SetThreadContext(m_hThre, &Context))
			{
				PutsError("设置线程上下文失败");

			}
			IsRepar = TRUE;
			SetBreakTF();


		}
	}

	return 1;
}

BOOL Debug::SetMemBreak(DWORD c_Address,char str[])
{
	BreakPoint bp = {c_Address,0,Mem,TRUE };
	
	DWORD c_Type = PAGE_NOACCESS;

	if (!_stricmp(str, "-x")) {
		c_Type = PAGE_READWRITE;
	}
	else if (!_stricmp(str, "-r"))
	{
		c_Type = PAGE_EXECUTE_WRITECOPY;
	}
	else if (!_stricmp(str, "-w"))
	{
		c_Type = PAGE_EXECUTE_READ;
	}
	else {
		c_Type = PAGE_NOACCESS;
	}
	bp.MemClas = c_Type;
	//修改内存属性为
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, c_Type, &bp.OldData))
	{
		PutsError("修改内存分页属性失败");
		return FALSE;
	}
	m_BreakPointAll.push_back(bp);

	return TRUE;
}

BOOL Debug::ReparMemBreak()
{
	//判断是否是我们下的内存断点   

	for (auto& i : m_BreakPointAll) {

		// 先筛选出内存断点
		if (i.BreakType == Mem) {

			//再判断是否在这一页内存上不是直接恢复属性 下TF断点
			if ((((DWORD)m_ExcepInfo.ExceptionInformation[1] & 0xFFFFF000)) == (i.Address & 0xFFFFF000))
			{
				DWORD ret = 0;
				if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, i.OldData, &ret))
				{
					PutsError("修改内存分页属性失败");
					return FALSE;
				}

				IsInputAndShowAsm = FALSE;

				// 如果断在了我们下断点的地址 说明我们需要接收用户输入
				if ((DWORD)m_ExcepInfo.ExceptionInformation[1] == i.Address)
				{
					//命中内存断点 需要接收用户输入
					IsInputAndShowAsm = TRUE;

				}
				

					SetBreakTF();
					IsRepar = TRUE;
				
			}
			
			
		}
	}


	return TRUE;
}

BOOL Debug::ReparSetBreak()
{

	for (auto& i : m_BreakPointAll)
	{
		//已经再次下断点不需要重复执行
		IsRepar = FALSE;

		// 如果是软件断点就把\xCC写回去
		if (i.BreakType == CcFlag && i.Execute)
		{
			// 临时变量
			SIZE_T ret = {};
			DWORD old = {};

			// 修改调试进程内存属性 
			if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, PAGE_READWRITE, &old)) {
				PutsError("设置内存分页属性失败");
				return FALSE;
			}

			//写入CC 下软件断点
			if (!WriteProcessMemory(m_hProc, (LPVOID)i.Address, "\xCC", 1, &ret)) {
				PutsError("写入进程内存CC失败");

				//把原来的内存属性还原回去
				VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, old, &old);

				return FALSE;
			}

			//把原来的内存属性还原回去
			VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, old, &old);
		}
		
		else if(i.BreakType == HdFlag&&i.Execute)
		{
			// 获取调试寄存器
			CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };

			//获取线程上下文
			if (!GetThreadContext(m_hThre, &ct))
			{
				PutsError("获取线程上下文失败");
				return FALSE;
			}

			//获取 Dr7 结构体并解析
			PDR7 Dr7 = (PDR7)& ct.Dr7;

			// 通过 Dr7 中的L(n) 知道当前的调试寄存器是否被使用
			if (ct.Dr0 == i.Address)
			{
				// 设置硬件断点是否有效
				Dr7->L0 = TRUE;
			}
			else if (ct.Dr1 == i.Address)
			{
				Dr7->L1 = TRUE;
			}
			else if (ct.Dr2 == i.Address)
			{
				Dr7->L2 = TRUE;
			}
			else if (ct.Dr3 == i.Address)
			{
				Dr7->L3 = TRUE;
			}
			/*else
			{
				PutsError("设硬件断点失败");
				return false;
			}*/

			//设置回去
			if (!SetThreadContext(m_hThre, &ct)) {
				PutsError("设置线程上下文失败");
				return FALSE;
			}
		}

		else if (i.BreakType == Mem&&i.Execute) {
			
				DWORD ret = {};
				//修改内存属性为
				if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, i.MemClas, &ret))
				{
					PutsError("修改内存分页属性失败");

					return FALSE;
				}
				
			
		}
	}
	return TRUE;
}

BOOL Debug::ClearBreak(DWORD c_Address)
{
	// 判断有没有被删除
	bool eflag = true;
	for (auto& i : m_BreakPointAll)
	{
		// 如果有断点
		if (i.Address == c_Address)
		{
			i.Execute = FALSE;
			eflag = true;
			printf("断点以失效\n");
			break;

		}
		else
			eflag = false;
	}
	if (!eflag)
	{
		printf("没有找到请重新输入\n:");
		return FALSE;
	}
	printf("断点以失效是否删除(y/n):");
	getchar();
	char c = 0;
	scanf("%c",&c);
	if(c=='y')
	{
		// 初始化向量
		std::vector<BreakPoint>::iterator iter = m_BreakPointAll.begin();

		// 遍历数组
		while (iter != m_BreakPointAll.end())
		{
			//判断是否需要删除
			if(!iter->Execute)
			{
				//如果是软件断点直接删除
				if (iter->BreakType == CcFlag)
				{
					// 从动态数组里面删除
					iter = m_BreakPointAll.erase(iter);
					break;
				}
				//如果是硬件断点就把寄存器也清空一下
				if(iter->BreakType == HdFlag)
				{

						// 获取到调试寄存器
						CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
						GetThreadContext(m_hThre, &Context);

						// 获取 Dr7 寄存器
						PDR7 Dr7 = (PDR7)& Context.Dr7;

						// 将触发的断点设置成无效的

						if (Context.Dr0 == iter->Address)
						{
							Dr7->L0 = 0;
						}
						else if (Context.Dr1 == iter->Address)
						{
							Dr7->L1 = 0;
						}
						else if (Context.Dr2 == iter->Address)
						{
							Dr7->L2 = 0;
						}
						else if (Context.Dr3 == iter->Address)
						{
							Dr7->L3 = 0;
						}
						else {
							printf("删除失败没有找到");
							eflag = false;
						}
						if (eflag) {
							// 将修改更新到线程
							if (!SetThreadContext(m_hThre, &Context))
							{
								PutsError("设置线程上下文失败");
								break;
							}
							iter = m_BreakPointAll.erase(iter);
							printf("删除成功!\n");
							return TRUE;
						}

						//CloseHandle(l_hThread);
					
				}

				if(iter->BreakType ==Mem)
				{
					//再判断是否在这一页内存上不是直接恢复属性 下TF断点
					
					
					DWORD ret = 0;
					if (!VirtualProtectEx(m_hProc, (LPVOID)iter->Address, 1, iter->OldData, &ret))
					{
						PutsError("删除内存断点失败");
						return FALSE;
					}
					// 从动态数组里面删除
					iter = m_BreakPointAll.erase(iter);
					return TRUE;

				}
			}
			
		}

	}

	return TRUE;
}

