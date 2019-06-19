#include "Debug.h"
#include <ShlObj_core.h>
#include <cstdio>
#include "debugRegisters.h"
#include <iostream>
#include<atlstr.h>

#include <DbgHelp.h>

//1. ����ͷ�ļ�
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

//��ʼ�� ��̬��Ա����
MyContext Debug::m_Myct = {};
char Debug::m_str[10] = {};

//���������Ϣ
char* GetError()
{
	// ���մ�������ַ����Ļ�����
	static char error[1024];
	LPSTR lpErrorString;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), // �������
		0, (LPSTR)& lpErrorString,
		0, NULL);

	strcpy_s(error, lpErrorString);
	LocalFree(lpErrorString);  // �ͷ��ڴ�
	return error;
}

//���������Ϣ
#define PutsError(error) \
			printf("�ļ���:%s\n������:%s\n�к�:%d\n����: %s\n%s\n", \
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
	// 1. ��ñ����̵�����
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return;
	// 2. ��ȡ��������
	TOKEN_ELEVATION_TYPE ElevationType = TokenElevationTypeDefault;
	BOOL                 bIsAdmin = false;
	DWORD                dwSize = 0;
	if (GetTokenInformation(hToken, TokenElevationType, &ElevationType,
		sizeof(TOKEN_ELEVATION_TYPE), &dwSize)) {
		// 2.1 ��������Ա��Ķ�ӦSID
		BYTE adminSID[SECURITY_MAX_SID_SIZE];
		dwSize = sizeof(adminSID);
		CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &dwSize);
		// 2.2 �жϵ�ǰ���������û���ɫ�Ƿ�Ϊ����Ա
		if (ElevationType == TokenElevationTypeLimited) {
			// a. ��ȡ�������Ƶľ��
			HANDLE hUnfilteredToken = NULL;
			GetTokenInformation(hToken, TokenLinkedToken, (PVOID)& hUnfilteredToken,
				sizeof(HANDLE), &dwSize);
			// b. ������ԭʼ�������Ƿ��������Ա��SID
			if (!CheckTokenMembership(hUnfilteredToken, &adminSID, &bIsAdmin))
				return;
			CloseHandle(hUnfilteredToken);
		}
		else {
			bIsAdmin = IsUserAnAdmin();
		}
		CloseHandle(hToken);
	}

	// 3. �жϾ����Ȩ��״��
	BOOL bFullToken = false;
	switch (ElevationType) {
	case TokenElevationTypeDefault: /* Ĭ�ϵ��û���UAC������ */
		if (IsUserAnAdmin())  bFullToken = true; // Ĭ���û��й���ԱȨ��
		else                  bFullToken = false;// Ĭ���û����ǹ���Ա��
		break;
	case TokenElevationTypeFull:    /* �Ѿ��ɹ���߽���Ȩ�� */
		if (IsUserAnAdmin())  bFullToken = true; //��ǰ�Թ���ԱȨ������
		else                  bFullToken = false;//��ǰδ�Թ���ԱȨ������
		break;
	case TokenElevationTypeLimited: /* �����������޵�Ȩ������ */
		if (bIsAdmin)  bFullToken = false;//�û��й���ԱȨ�ޣ�������Ȩ������
		else           bFullToken = false;//�û����ǹ���Ա�飬�ҽ���Ȩ������
	}
	// 4. ����Ȩ�޵Ĳ�ͬ���ư�ť����ʾ
	if (!bFullToken) {
		MessageBoxW(0, L"Un Admin", L"��ʾ", 0);

		// 2. ��ȡ��ǰ����·��
		char szApplication[MAX_PATH] = { 0 };
		DWORD cchLength = _countof(szApplication);
		QueryFullProcessImageName(GetCurrentProcess(), 0, szApplication, &cchLength);
		// 3. �Թ���ԱȨ�����´򿪽���
		SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
		sei.lpVerb = "runas";      // ��������Ȩ��
		sei.lpFile = szApplication; // ��ִ���ļ�·��
		sei.lpParameters = NULL;          // ����Ҫ����
		sei.nShow = SW_SHOWNORMAL; // ������ʾ����
		if (ShellExecuteEx(&sei))
			exit(0);
		else
			MessageBoxW(0, L"??????", L"��ʾ", 0);
	}
	//else
		//MessageBoxW(0, L"Admin", L"��ʾ", 0);

}

BOOL Debug::PromotionDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;    HANDLE hToken;
	// ���޸�Ȩ�޵ķ�ʽ���򿪽��̵�����
	if (OpenProcessToken(GetCurrentProcess(), 0,
		&hToken)) {
		// ����Ȩ�޽ṹ��
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		//���LUID
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL); //�޸�Ȩ��
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

BOOL Debug::Open(char FilePath[])
{
	//˵�����Դ������̵ķ�ʽ�򿪵�
	IsOpera = TRUE;

	//���մ������̵���Ϣ
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = { 0 };

	//�Ե��Է�ʽ����һ������
	BOOL ret = CreateProcess(FilePath,NULL,NULL,NULL,FALSE,
		DEBUG_ONLY_THIS_PROCESS| CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);

	//����ʧ�ܷ��ؼ�
	if(!ret)
	{
		MessageBox(0, "��������ʧ��!", "������ʾ", 0);
		return FALSE;
	}
	m_hProcess = pi.hProcess;

	return TRUE;
}

BOOL Debug::Open(DWORD Pid)
{
	//����Pid�� ע��ʹ��
	m_iard = Pid;

	IsOpera = FALSE;
	return DebugActiveProcess(Pid);
}

VOID Debug::WaitForEvent()
{

	//ѭ�������쳣��Ϣ
	while(true)
	{
		
		//�ȴ������¼�
		WaitForDebugEvent(&m_dbgEvent, INFINITE);

		//���߳̽��̾�� ��ȡ���޸� ��Ϣ
		m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dbgEvent.dwProcessId);
		m_hThre = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dbgEvent.dwThreadId);

		switch(m_dbgEvent.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT:
			{
					//printf("�쳣�¼�:\n");

					//���ù��˺���
					FilterException();
		
					break;
				}
			case CREATE_THREAD_DEBUG_EVENT:
				printf("�̴߳���\n");
				break;
			case CREATE_PROCESS_DEBUG_EVENT:
				printf("���̴���\n");
				//DLLע��
				DllInject();

				//��ʼ������
				SymInitialize(m_hProcess, NULL, FALSE);

				DWORD g_ImageBase = (DWORD)m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage;//���澵���ַ
				//DWORD g_OEP = (DWORD)m_dbgEvent.u.CreateProcessInfo.lpStartAddress;///�������OEP
				//����������ģ�������Ϣ
				DWORD64 moduleAddress = SymLoadModule64(m_hProcess,m_dbgEvent.u.CreateProcessInfo.hFile, NULL, NULL, g_ImageBase, 0);
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				printf("�߳��˳�\n");
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				{
					printf("�����˳�\n");

						//�����⵽�����˳� ��ô���Ǿͽ�������
					goto EfNOP;
				}
			case LOAD_DLL_DEBUG_EVENT:
				printf("DLL����\n");
				SymLoadModule64(m_hProcess, m_dbgEvent.u.LoadDll.hFile, NULL, NULL, (DWORD64)m_dbgEvent.u.LoadDll.lpBaseOfDll, 0);
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				printf("DLLж��\n");
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				printf("������Ϣ\n");
				break;
		}
		
		//�ظ�������ϵͳ 
		//DBG_CONTINUE
		//DBG_EXCEPTION_NOT_HANDLED
		ContinueDebugEvent(m_dbgEvent.dwProcessId, m_dbgEvent.dwThreadId, m_ReplyInfo);

	
		//�رմ򿪵��߳̽��̾��
		CloseHandle(m_hProc);

		CloseHandle(m_hThre);




	}
	EfNOP:
	return;
}

VOID Debug::FilterException()
{
	//�ӵ����쳣��Ϣ�л�ȡ���쳣��Ϣ
	m_ExcepInfo = m_dbgEvent.u.Exception.ExceptionRecord;

	//��ʱ���� �����ڴ��쳣 
	//�ϵ��Ƿ���Ҫ�����ڴ�ҳΪ�쳣 
	//Ϊ��һ����׼�� Ĭ�ϲ���Ҫ����
	//bool IsMemException = false;

	switch(m_ExcepInfo.ExceptionCode)
	{
		//����ϵ� int3 //������Լ�������һ��
	case EXCEPTION_BREAKPOINT:

		//�ж��Ƿ���ϵͳ�ϵ�
		if(IssystemBp)
		{
			IssystemBp = false;
			printf("����ϵͳ�ϵ�:%08X\n",(DWORD)m_ExcepInfo.ExceptionAddress);

			//����peb
			PROCESS_BASIC_INFORMATION peb;

			DWORD dw;
			NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &peb, sizeof(peb), &dw);

			DWORD pISdbg = ((DWORD)peb.PebBaseAddress + 0x2);
			WriteProcessMemory(m_hProcess, (LPVOID)pISdbg, "\x0", 2, &dw);
			
			//��ʾ��������
			GetHelp();

			//���ز��
			LoadPlugin();

		}else
		{
			//ȷ���Ƿ��������Լ��µĶϵ� 
			//�ָ�ԭ��������
			ReparBreak();
		}

		break;

		//Ӳ���ϵ� 4�� �����쳣
	case EXCEPTION_SINGLE_STEP:
	{
		IsInputAndShowAsm = TRUE;

		if (!IsTF) {

			IsHPBreak = FALSE;

			for (auto& i : m_BreakPointAll) {
				if ((DWORD)m_ExcepInfo.ExceptionAddress == i.Address && i.BreakType == HdFlag) {

					//����쳣��ַ��ͬ˵����Ҫ�޸�
					ReparBreakHD();

				}
				else
					IsHPBreak = TRUE;
			}
			//�ٴ������жϵ�
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
		//����û��Ȩ�޵������ַ �ڴ�ϵ�
	case EXCEPTION_ACCESS_VIOLATION:

		ReparMemBreak();

		break;
	default:
		m_ReplyInfo = DBG_EXCEPTION_NOT_HANDLED;
		break;
	}

	if (IsInputAndShowAsm) {
		//��ʾ�����
		ShowAsm();

		//�ȴ��û�����
		GetCommand();
	}

	return ;      
}

VOID Debug::ShowAsm()
{
	//��ʾ�Ĵ�����Ϣ
	CONTEXT ct = {};

	//��ȡȫ���Ĵ�����Ϣ
	ct.ContextFlags = CONTEXT_ALL;

	PEFLAGS PEflags = (PEFLAGS)&ct.EFlags;

	GetThreadContext(m_hThre, &ct);

	//�������ʾ����
	printf("-----------------------�Ĵ���-------------------------");						printf("-----------------EFlags-----------------------\n");
	printf("|Eax:%08X Ecx:%08X Edx:%08X Ebx:%08X|\t", ct.Eax, ct.Ecx, ct.Edx, ct.Ebx);		printf("ZF %d  PF %d  AF %d  OF %d  SF %d\n",PEflags->ZF,PEflags->PF,PEflags->AF,PEflags->OF,PEflags->SF);
	printf("|Esp:%08X Ebp:%08X Esi:%08X Edi:%08X|\t", ct.Esp, ct.Ebp, ct.Esi, ct.Edi);		printf("DF %d  CF %d  TF %d  IF %d  \n",PEflags->DF,PEflags->CF,PEflags->TF,PEflags->IF);
	printf("             |EIP:");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xC);
	printf("%08X\n\n", ct.Eip);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x7);

	//��ʾ�������Ϣ
	char buff[10 * 15] = {};
	SIZE_T ret = 0;

	//��ȡ�ڴ��еĻ�����
	if(!ReadProcessMemory(m_hProc, (LPVOID)m_ExcepInfo.ExceptionAddress,buff,sizeof(buff),&ret))
	{
		PutsError("��ȡ�����ڴ�ʧ��");
		return;
	}

	//ʹ�÷������������������Ϣ
	DISASM disasm = {};
	
	//����Ҫ���з�����Opcode���ڴ��ַ
	disasm.EIP = (UIntPtr)buff;

	//���õ�ǰָ�����ڵ�ַ
	disasm.VirtualAddr = (UInt64)m_ExcepInfo.ExceptionAddress;	//�쳣��ַ

	//���ð���32λ����������з����
	disasm.Archi = 0;

	int nCount = 0;

	//Ĭ��������ɫ�ǰ�ɫ
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

		//��ͬ�����ͬ����ɫ
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

		//�ָ�ԭ���İ�ɫ
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x7);

		disasm.EIP += nLen;
		disasm.VirtualAddr += nLen;
		++nCount;
	}


	return ;
}

VOID Debug::ShowAsm(DWORD c_Address, DWORD c_Len)
{
	

	//��ʾ�������Ϣ
	char buff[100 * 15] = {};
	SIZE_T ret = 0;

	if (c_Len > 100)
		return;

	//��ȡ�ڴ��еĻ�����
	if (!ReadProcessMemory(m_hProc, (LPVOID)c_Address, buff, sizeof(buff), &ret))
	{
		PutsError("��ȡ�����ڴ�ʧ��");
		return;
	}

	//ʹ�÷������������������Ϣ
	DISASM disasm = {};

	//����Ҫ���з�����Opcode���ڴ��ַ
	disasm.EIP = (UIntPtr)buff;

	//���õ�ǰָ�����ڵ�ַ
	disasm.VirtualAddr = (UInt64)c_Address;	//�쳣��ַ

	//���ð���32λ����������з����
	disasm.Archi = 0;

	int nCount = 0;

	//Ĭ��������ɫ�ǰ�ɫ
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

		//��ͬ�����ͬ����ɫ
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

		//�ָ�ԭ���İ�ɫ
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x7);

		disasm.EIP += nLen;
		disasm.VirtualAddr += nLen;
		++nCount;
	}

	return ;
}

VOID Debug::GetCommand()
{
	//��ȡ�û����뻺����
	char cmd[40]={};
	printf(">");

	DWORD Address = 0;
	char str[3] = {};
	DWORD c_Type = 0;
	DWORD c_Len = 0;

	while(true)
	{
		scanf("%s",cmd);

		if(!_stricmp("t", cmd))			//����ִ�жϵ�
		{
			SetBreakTF();
			IsTF = TRUE;
			break;
		}else if(!_stricmp("tg",cmd))
		{
			if(!SetStepTF())
			{
				printf("����ʧ�� !");
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
		else if (!_stricmp("bp", cmd))	//����ϵ�  
		{
			scanf("%X",&Address);		//�����û������ַ

			SetBreakInt3(Address);		//���뺯����ʼ������ϵ�
		}
		else if(!_stricmp("hp", cmd))	//Ӳ���ϵ�
		{
			
			scanf("%X%s", &Address, str);

			// �����û��������öϵ�����  printf("1�ֽ�:0|2�ֽ�:1|4�ֽ�:3");
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
		else if (!_stricmp("np", cmd))	//���ڴ�ϵ�
		{
			scanf("%X%s", &Address, str);
			SetMemBreak(Address,str);
		}
		else if(!_stricmp("bpt",cmd))
		{
			scanf("%X", &Address);
			SetBreakInt3(Address, true, true);
		}
		else if(!_stricmp("fp", cmd))	//�鿴���жϵ�
		{
			//�鿴���жϵ�
			FindBreak();
		}
		else if(!_stricmp("dp",cmd))	//ɾ���ϵ�
		{
			scanf("%X",&Address);
			ClearBreak(Address);

		}
		else if(!_stricmp("xasm",cmd))	//�޸Ļ��
		{
			AlterAsm();
		}else if(!_stricmp("fm",cmd))	//�鿴�ڴ�
		{
			scanf("%X", &Address);
			ShowMem(Address);
		}
		else if (!_stricmp("xm", cmd))  //�޸��ڴ�
		{
			scanf("%X", &Address);
			AlterMem(Address);
			ShowAsm();
		}else if(!_stricmp("fz",cmd))  //�鿴�ڴ�
		{
			scanf("%d", &c_Len);
			ShowStack(c_Len);
		}else if(!_stricmp("xr",cmd))  //�޸ļĴ���
		{
			AlterRegister();
			ShowAsm();
		}else if(!_stricmp("fmd",cmd))	//�鿴ģ��
		{
			GetModuleList();
		}else if(!_stricmp("h",cmd))	//�鿴����
		{
			GetHelp();
		}else if(!_stricmp("fpe",cmd))  //�鿴PE��Ϣ
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
	printf("t:   ��������\n");
	printf("tg:  ��������\n");
	printf("g:   ����ִ��\n");
	printf("cls: ����\n");
	printf("fasm:��ַ �鿴ָ����ַ�����Ϣ\n");
	printf("bp:   ����ϵ�|| �����ϵ� (1) \n");
	printf("hp:   -x|-r n |-w n ִ�� ��|д\n");
	printf("np:   -x|-r |-w  �ڴ�ϵ�\n");
	printf("fp:  �鿴���жϵ�\n");
	printf("dp:  ��ַ ɾ��ָ���ϵ�Ͳ鿴���ʹ��\n");
	printf("xasm:�޸Ļ�����\n");
	printf("fm:  ��ַ �鿴�ڴ�����(Ĭ��16���ֽ�)\n");
	printf("xm:  ��ַ �޸��ڴ�����\n");
	printf("fz:  (n)�鿴ջ\n");
	printf("xr:  �޸ļĴ���\n");
	printf("fmd: �鿴ģ����Ϣ\n");
	printf("fpe: ��ַ ��С �鿴PE��Ϣ\n");
	printf("plugin: ʹ�ò��");
	return ;
}

VOID Debug::FindBreak()
{
	//������жϵ���ϢLocal(0)/global(1)


	char pType[20] = {};

	printf("-------����{%d}���ϵ�-------\n", m_BreakPointAll.size());

	//�����ϵ㶯̬����
	for (auto& i : m_BreakPointAll) {

		switch(i.BreakType)
		{
		case 0:strcpy(pType, "����ϵ�");
			break;
		case 1:strcpy(pType, "Ӳ���ϵ�");
			break;
		case 2:strcpy(pType, "�ڴ�ϵ�");
			break;
		}

		printf("|Address:%08X|%d|Type:%s\n", i.Address,i.Execute,pType);
	}
	return ;
}

VOID Debug::AlterMem(DWORD c_Address)
{
	//��ʱ����
	SIZE_T size = {};
	DWORD Oldproperty = {};

	DWORD str = {};

	//BYTE* l_Mem;
	//�޸ĵ��Խ����ڴ����� 
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, PAGE_READWRITE, &Oldproperty)) {
		PutsError("�����ڴ��ҳ����ʧ��");
		return;
	}

	printf(":");
	scanf("%X",&str);

	//д
	if (!WriteProcessMemory(m_hProc, (LPVOID)c_Address, &str, 1, &size)) {
		PutsError("�޸��ڴ�����ʧ��");

		//��ԭ�����ڴ����Ի�ԭ��ȥ
		VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, Oldproperty, &Oldproperty);

		return ;
	}

	
	//��ԭ�����ڴ����Ի�ԭ��ȥ
	VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, Oldproperty, &Oldproperty);

	return;
}

VOID Debug::ShowStack(const DWORD Size)
{
	DWORD size;

	DWORD l_stack[100] = {};

	//��ʾ�Ĵ�����Ϣ
	CONTEXT ct = { CONTEXT_CONTROL };

	//��ȡ��ǰ�߳�������
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

	//�����û�����ļĴ���
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
		printf("û���ҵ�����������\n:");
		goto aaa;
	}

	if(!SetThreadContext(m_hThre, &ct))
	{
		PutsError("�޸ļĴ�������");
		return;
	}

	printf("�޸����");
	return ;
}

VOID Debug::GetModuleList()
{
	setlocale(LC_ALL, "chs");

	HANDLE        hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	// 1. ����һ��ģ����صĿ��վ��
	hModuleSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,  // ָ�����յ�����
		m_dbgEvent.dwProcessId);            // ָ������
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return ;

	// ͨ��ģ����վ����ȡ��һ��ģ����Ϣ
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return;
	}
	// ѭ����ȡģ����Ϣ
	do {
		wprintf(L"ģ������:%S \t ģ���ַ:%08X\t ģ���С��%08X\n",
			me32.szModule,me32.modBaseAddr, me32.modBaseSize);
	} while (Module32Next(hModuleSnap, &me32));

	// �رվ�����˳�����
	CloseHandle(hModuleSnap);

	return ;
}

BOOL Debug::DllInject()
{

	HANDLE hProcess = NULL;

	//�ж�����ʲô��ʽ�򿪵ľ��
	if (IsOpera) {
		hProcess = m_hProcess;
	}
	else {
		//1.�򿪽���
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_iard);
		m_hProcess = hProcess;
	}
	//2.��Ŀ�����������ռ�
	LPVOID pAddr = VirtualAllocEx(hProcess, NULL, 200, MEM_COMMIT, PAGE_READWRITE);

	//3.��Ŀ�������д��dll·��
	CHAR dllPath[] = "test.dll";
	SIZE_T dwSzie = 0;
	WriteProcessMemory(hProcess, pAddr, dllPath, sizeof(dllPath), &dwSzie);

	//4.����Զ���̣߳�ע��dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		pAddr,
		NULL, NULL);

	//5.�رվ�����ͷſռ�
	//WaitForSingleObject(hThread, -1);
	CloseHandle(hThread);

	return 0;
}

VOID Debug::Analysis_Export_Import(DWORD c_Address, DWORD c_BaseSize)
{
	//����ѿռ�
	m_pFile = new char[c_BaseSize]{};
	SIZE_T dwdize=0;
	DWORD dwold=0;

	if(!VirtualProtectEx(m_hProcess,(LPVOID)c_Address, c_BaseSize,PAGE_EXECUTE_READWRITE,&dwold))
	{
		PutsError("�޸��ڴ����Գ���")
	}

	if(!ReadProcessMemory(m_hProcess, (LPVOID)c_Address, m_pFile, c_BaseSize,&dwdize))
	{
		PutsError("��ȡ�ڴ����");
	}

	if(!VirtualProtectEx(m_hProcess, (LPVOID)c_Address, c_BaseSize, dwold, &dwold))
	{
		PutsError("�޸��ڴ����Գ���")
	}


	m_pDos = (PIMAGE_DOS_HEADER)m_pFile;
	m_pNT = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pFile);


	printf("������\n");

	//1.��ȡ����Ŀ¼���һ���ֶ� �õ�������RVA
	DWORD ExportDir = m_pNT->OptionalHeader.DataDirectory[0].VirtualAddress;

	if (!ExportDir)
	{
		printf("û�е����!");
		return;
	}

	//2.��ȡ�������ļ�λ��
	PIMAGE_EXPORT_DIRECTORY l_pExport = (PIMAGE_EXPORT_DIRECTORY)(ExportDir+m_pFile);

	//3.��ȡPE�ļ�����
	printf("%s\n", (char*)(l_pExport->Name + m_pFile));

	//4.��ȡ��Ż���
	printf("��Ż���:%08x\n", l_pExport->Base);

	//5.����������е�������

	//5.1���������ܸ���
	DWORD FunLen = l_pExport->NumberOfFunctions;

	//5.2�����������Ƹ���
	DWORD NameFunLen = l_pExport->NumberOfNames;

	//6.��ȡ����������ַ���ַ
	PDWORD pFunAddress = (PDWORD)(l_pExport->AddressOfFunctions + m_pFile);
	PDWORD pFunName = (PDWORD)(l_pExport->AddressOfNames + m_pFile);
	PWORD  pOrdinals = (PWORD)(l_pExport->AddressOfNameOrdinals + m_pFile);

	//����������е�������

	for (int i = 0; i < FunLen; i++)
	{
		//���������ַΪ0 ˵��������ַ��Ч Ѱ����һ��
		if (pFunAddress[i] == 0)
			continue;

		printf("�������:%d\t", i + l_pExport->Base);

		bool Flag = false;
		for (int j = 0; j < NameFunLen; j++)
		{
			if (pOrdinals[j] == i)
			{
				printf("��������:%s\t", (char*)(pFunName[j] + m_pFile));
				Flag = true;
			}

		}
		if (!Flag)
			printf("��������:û��\t");

		printf("������ַ:%08x\n",(pFunAddress[i] + m_pFile));

	}

	printf("�����\n");
	//1.��ȡ����Ŀ¼��ڶ����ֶ� �õ������RVA
	DWORD ImportDir = m_pNT->OptionalHeader.DataDirectory[1].VirtualAddress;

	if(!ImportDir)
	{
		printf("û�е����!");
		return ;
	}

	//2.��ȡ������ļ�λ��
	PIMAGE_IMPORT_DESCRIPTOR l_pImport = (PIMAGE_IMPORT_DESCRIPTOR)(ImportDir + m_pFile);

	//���������� ����ĺ���
	while (l_pImport->Name)
	{
		//��ӡģ����
		printf("\n\t\tģ������:%s\n", (char*)(l_pImport->Name + m_pFile));

		//�������뺯��
		PIMAGE_THUNK_DATA l_pThunk = (PIMAGE_THUNK_DATA)(l_pImport->OriginalFirstThunk + m_pFile);

		while (l_pThunk->u1.AddressOfData)
		{
			//�жϵ��뷽ʽ   (���λ�Ƿ�Ϊ1 )1 ����ŵ��� 0�Ǻ���������
			if (IMAGE_SNAP_BY_ORDINAL(l_pThunk->u1.AddressOfData))
			{
				//����� l_pThunk->ul.Ordinal 
				printf("\t���뺯������:[NULL]\t���뺯�����:%d\n", l_pThunk->u1.Ordinal && 0xFFFF);
			}
			else
			{
				//���Ƶ��� 
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(l_pThunk->u1.AddressOfData + m_pFile);

				printf("\t���뺯������:[%s]\t���뺯�����:%d\n", pName->Name, pName->Hint);
			}

			//��һ������
			l_pThunk++;
		}

		//��һ������ṹ
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
	//��ʱ����
	SIZE_T size = {};
	DWORD Oldproperty = {};

	unsigned char l_Mem[16] = {};
	//BYTE* l_Mem;
	//�޸ĵ��Խ����ڴ����� 
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, PAGE_READWRITE, &Oldproperty)) {
		PutsError("�����ڴ��ҳ����ʧ��");
		return ;
	}

	//��ȡ��16���ֽ� ��������
	if (!ReadProcessMemory(m_hProc, (LPVOID)c_Address, &l_Mem, 16, &size)) {
		PutsError("��ȡ�����ڴ�ʧ��");
		return ;
	}
	printf("%08X:\n", c_Address);
	//�����ֽ������Ϣ
	for(int i=0;i<16;i++)
	{
		printf("[%02d]%02X ",i, l_Mem[i]);
		
		if ((i+1)%8==0)
			printf("\n");
	}
	printf("\n");
	printf("%S\t%s\n", l_Mem,l_Mem);
	//��ԭ�����ڴ����Ի�ԭ��ȥ
	VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, Oldproperty, &Oldproperty);


	return ;
}

VOID Debug::AlterAsm()
{
	printf("��������Ҫ�޸Ļ��ĵ�ַ\n:");
	//��������
	XEDPARSE xed = { 0 };

	// ��������opcode�ĵĳ�ʼ��ַ
	scanf_s("%llx", &xed.cip);

	getchar();

	DWORD OldPage = 0;
	DWORD ret = 0;

	do
	{
		aaa:
		// ����ָ��
		printf("ָ�");
		gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

		if (!strcmp(xed.instr,"exit"))
			break;

		// xed.cip, ��������תƫ�Ƶ�ָ��ʱ,��Ҫ��������ֶ�
		if (XEDPARSE_OK != XEDParseAssemble(&xed))
		{
			printf("ָ�����%s\n", xed.error);
			goto aaa;
		}

		// ��ӡ���ָ�������ɵ�opcode
		//printf("%08X : ", xed.cip);
		//printOpcode(xed.dest, xed.dest_size);
		//printf("\n");

		if(!VirtualProtectEx(m_hProc, (LPVOID)xed.cip, xed.dest_size, PAGE_READWRITE, &OldPage))
		{
			PutsError("�޸��ڴ�����ʧ��");
			return;
		}

		
		if (!WriteProcessMemory(m_hProc, (LPVOID)xed.cip, xed.dest, xed.dest_size, &ret)) {
			PutsError("д����ʧ��");

			//��ԭ�����ڴ����Ի�ԭ��ȥ
			VirtualProtectEx(m_hProc, (LPVOID)xed.cip, xed.dest_size, OldPage, &OldPage);

			return;
		}

		//��ԭ�����ڴ����Ի�ԭ��ȥ
		VirtualProtectEx(m_hProc, (LPVOID)xed.cip, xed.dest_size, OldPage, &OldPage);



		// ����ַ���ӵ���һ��ָ����׵�ַ
		xed.cip += xed.dest_size;
	} while (*xed.instr);

	ShowAsm();

	return ;
}

BOOL Debug::SetBreakTF()
{
	//��ȡ�߳������Ĳ�����TF ��־λ
	CONTEXT ct = { CONTEXT_CONTROL };

	//��ȡ�߳�������
	if(!GetThreadContext(m_hThre, & ct))
	{
		PutsError("��ȡ�߳�������ʧ��");
		return FALSE;
	}

	//����TF �����ϵ�
	EFLAGS* pEflag = (EFLAGS*)& ct.EFlags;
	pEflag->TF = 1;

	//���û�ȥ
	if (!SetThreadContext(m_hThre, &ct)) {
		PutsError("�����߳�������ʧ��");
		return FALSE;
	}

	return TRUE;
}

BOOL Debug::SetStepTF()
{

	BreakPoint bp;

	//��ʾ�������Ϣ
	char buff[1 * 15] = {};
	SIZE_T ret = 0;

	//��ȡ�ڴ��еĻ�����
	if (!ReadProcessMemory(m_hProc, (LPVOID)m_ExcepInfo.ExceptionAddress, buff, sizeof(buff), &ret))
	{
		PutsError("��ȡ�����ڴ�ʧ��");
		return FALSE;
	}

	//ʹ�÷������������������Ϣ
	DISASM disasm = {};

	//����Ҫ���з�����Opcode���ڴ��ַ
	disasm.EIP = (UIntPtr)buff;

	//���õ�ǰָ�����ڵ�ַ
	disasm.VirtualAddr = (UInt64)m_ExcepInfo.ExceptionAddress;	//�쳣��ַ

	//���ð���32λ����������з����
	disasm.Archi = 0;

	


	int nLen = Disasm(&disasm);
	if (nLen == -1) {
		return FALSE;
	}

	//����call

	if (!strncmp("call", disasm.CompleteInstr, 4)|| !strncmp("rep", disasm.CompleteInstr, 3)) {
	
		//��call
		SetBreakInt3(disasm.VirtualAddr + nLen, false);
	}
	else {
		//����call ˵������Ҫ���� ֱ�ӵ���ִ��
		SetBreakTF();

		//˵���������Լ��µ�TF Ӳ���ϵ�
		IsTF = TRUE;
	}
	//disasm.EIP + nLen;
	//disasm.VirtualAddr + nLen;
	
	//�ɹ�������
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

	//�ж�һ�����ǲ���һ�������ϵ� ����������ϵ��Ӧ��
	if(c_CondiTion)
	{
		printf("��ѡ����������:(1.ִ�д���|2.ĳ���Ĵ�����ֵ):");

		scanf("%d", &IsConDitionType);

		if (IsConDitionType == 1) {

			printf("���������ִ�д���\n:");
			scanf("%d", &IsConDiTion);

		}else if(IsConDitionType==2)
		{
			
			//�����û�����ļĴ���
			
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
				printf("û����������Ĵ���\n����������\n:");
				goto aaa;
			}
		}
	}

	//����ϵ���Ϣ 
	BreakPoint bp ={c_Address,0,CcFlag ,c_Execute,0,c_CondiTion };

	//��ʱ����
	SIZE_T size = {};
	DWORD old = {};

	//�޸ĵ��Խ����ڴ����� 
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, PAGE_READWRITE, &old)) {
		PutsError("�����ڴ��ҳ����ʧ��");
		return FALSE;
	}

	//��ȡ��һ���ֽ� ��������
	if (!ReadProcessMemory(m_hProc, (LPVOID)c_Address, &bp.OldData, 1, &size)) {
		PutsError("��ȡ�����ڴ�ʧ��");
		return FALSE;
	}

	//д��CC ������ϵ�
	if (!WriteProcessMemory(m_hProc, (LPVOID)c_Address, "\xCC", 1, &size)) {
		PutsError("д������ڴ�CCʧ��");
		
		//��ԭ�����ڴ����Ի�ԭ��ȥ
		VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, old, &old);

		return FALSE;
	}

	//��ԭ�����ڴ����Ի�ԭ��ȥ
	VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, old, &old);


	m_BreakPointAll.push_back(bp);

	return TRUE;
}

BOOL Debug::ReparBreak()
{
	//ѭ��������̬����
	//��һ���ǲ����Լ��µ�
	//�����  �ͻ�ԭ��ȥ 
	//���Ұ�EIP-1 ��Ϊint�������쳣 Eipָ����һ��

	for(auto&i:m_BreakPointAll)
	{
		if(i.BreakType==CcFlag&&i.Address==(DWORD)m_ExcepInfo.ExceptionAddress)
		{
			//��ʱ����
			SIZE_T ret = {};
			DWORD old = {};

			//�޸ĵ��Խ����ڴ����� 
			if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, PAGE_READWRITE, &old)) {
				PutsError("�����ڴ��ҳ����ʧ��");
				return FALSE;
			}

			//д��ԭ����ֵ
			if (!WriteProcessMemory(m_hProc, (LPVOID)i.Address, &i.OldData, 1, &ret)) {
				PutsError("��ԭint3�ϵ�����ʧ��");
				return FALSE;
			}

			//��ԭ�����ڴ����Ի�ԭ��ȥ
			VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, old, &old);

			//EIP-1
			CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_ALL;
			GetThreadContext(m_hThre, &ct);
			ct.Eip--;
			SetThreadContext(m_hThre, &ct);

			//TF �������Ժ���Ҫ �ٴ��¶ϵ�
			IsRepar = TRUE;
			SetBreakTF();

			static DWORD CondiTionLen = 0;

			

			//���Ϊ��˵������һ�������ϵ�
			if(i.IsCondition)
			{	
				if (IsConDitionType == 1) {
					//ֻҪ�ϵ�����ϵ�  ��������+1
					CondiTionLen++;

					//������д��������õ�ִ�д�����ͬ 
					if (CondiTionLen == IsConDiTion)
					{
						//˵�� ��Ҫ�����û�����
						IsInputAndShowAsm = TRUE;

						//˵�� �ϵ�Ŀ���Ѿ��ﵽ ����Ҫ�ٴ��¶ϵ�
						i.Execute = FALSE;
					}
					else
						IsInputAndShowAsm = FALSE;
				}else if(IsConDitionType==2)
				{

					//��ȡ�߳������Ĳ�����TF ��־λ
					CONTEXT ct = { CONTEXT_ALL };

					//��ȡ�߳�������
					if (!GetThreadContext(m_hThre, &ct))
					{
						PutsError("��ȡ�߳�������ʧ��");
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
						//˵�� ��Ҫ�����û�����
						IsInputAndShowAsm = TRUE;

						//˵�� �ϵ�Ŀ���Ѿ��ﵽ ����Ҫ�ٴ��¶ϵ�
						i.Execute = FALSE;

						//��ʱ��Ҫ��ʼ�� �Լ���
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
	
	//�Զϵ㳤�Ƚ��д���
	if(c_Len==1)	
	{
		c_Address -= c_Address % 2;
	}else if(c_Len==3)
	{
		c_Address -= c_Address % 4;
	}
	
	// ���ԼĴ��� Dr0-DR7 

	// ���ڱ���ԭ���ڴ������
	BreakPoint HdInfo = { c_Address,0,HdFlag,TRUE,0};

	// ��ȡ���ԼĴ���
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };

	//��ȡ�߳�������
	if (!GetThreadContext(m_hThre, &ct))
	{
		PutsError("��ȡ�߳�������ʧ��");
		return FALSE;
	}

	//��ȡ Dr7 �ṹ�岢����
	PDR7 Dr7 = (PDR7)& ct.Dr7;

	// ͨ�� Dr7 �е�L(n) ֪����ǰ�ĵ��ԼĴ����Ƿ�ʹ��
	if (Dr7->L0 == FALSE)
	{
		// ����Ӳ���ϵ��Ƿ���Ч
		Dr7->L0 = TRUE;

		// ���öϵ������
		Dr7->RW0 = c_Type;

		// ���öϵ��ַ�Ķ��볤��
		Dr7->LEN0 = c_Len;

		// ���öϵ�ĵ�ַ
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
		PutsError("Ӳ���ϵ��Ѿ���4����");
		return false;
	}

	//���û�ȥ
	if (!SetThreadContext(m_hThre, &ct)) {
		PutsError("�����߳�������ʧ��");
		return FALSE;
	}


	//�����Ҫ�޸�һ��Ӳ���ϵ�
	//IsHPBreak = TRUE;
	m_BreakPointAll.push_back(HdInfo);

	return TRUE;
}

BOOL Debug::ReparBreakHD()
{
	for (auto& i : m_BreakPointAll) {
		// �����Ӳ���ϵ������Ϊ��Ч
		if (i.BreakType == HdFlag && i.Address == (DWORD)m_ExcepInfo.ExceptionAddress)
		{
			//���߳̾��
			//HANDLE l_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,m_hThre);

			// ��ȡ�����ԼĴ���
			CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
			GetThreadContext(m_hThre, &Context);

			// ��ȡ Dr7 �Ĵ���
			PDR7 Dr7 = (PDR7)& Context.Dr7;

			//// ���� Dr6 �ĵ� 4 λ֪����˭��������
			//int index = Context.Dr6 & 0xF;


			// �������Ķϵ����ó���Ч��

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
	
			// ���޸ĸ��µ��߳�
			if (!SetThreadContext(m_hThre, &Context))
			{
				PutsError("�����߳�������ʧ��");

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
	//�޸��ڴ�����Ϊ
	if (!VirtualProtectEx(m_hProc, (LPVOID)c_Address, 1, c_Type, &bp.OldData))
	{
		PutsError("�޸��ڴ��ҳ����ʧ��");
		return FALSE;
	}
	m_BreakPointAll.push_back(bp);

	return TRUE;
}

BOOL Debug::ReparMemBreak()
{
	//�ж��Ƿ��������µ��ڴ�ϵ�   

	for (auto& i : m_BreakPointAll) {

		// ��ɸѡ���ڴ�ϵ�
		if (i.BreakType == Mem) {

			//���ж��Ƿ�����һҳ�ڴ��ϲ���ֱ�ӻָ����� ��TF�ϵ�
			if ((((DWORD)m_ExcepInfo.ExceptionInformation[1] & 0xFFFFF000)) == (i.Address & 0xFFFFF000))
			{
				DWORD ret = 0;
				if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, i.OldData, &ret))
				{
					PutsError("�޸��ڴ��ҳ����ʧ��");
					return FALSE;
				}

				IsInputAndShowAsm = FALSE;

				// ��������������¶ϵ�ĵ�ַ ˵��������Ҫ�����û�����
				if ((DWORD)m_ExcepInfo.ExceptionInformation[1] == i.Address)
				{
					//�����ڴ�ϵ� ��Ҫ�����û�����
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
		//�Ѿ��ٴ��¶ϵ㲻��Ҫ�ظ�ִ��
		IsRepar = FALSE;

		// ���������ϵ�Ͱ�\xCCд��ȥ
		if (i.BreakType == CcFlag && i.Execute)
		{
			// ��ʱ����
			SIZE_T ret = {};
			DWORD old = {};

			// �޸ĵ��Խ����ڴ����� 
			if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, PAGE_READWRITE, &old)) {
				PutsError("�����ڴ��ҳ����ʧ��");
				return FALSE;
			}

			//д��CC ������ϵ�
			if (!WriteProcessMemory(m_hProc, (LPVOID)i.Address, "\xCC", 1, &ret)) {
				PutsError("д������ڴ�CCʧ��");

				//��ԭ�����ڴ����Ի�ԭ��ȥ
				VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, old, &old);

				return FALSE;
			}

			//��ԭ�����ڴ����Ի�ԭ��ȥ
			VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, old, &old);
		}
		
		else if(i.BreakType == HdFlag&&i.Execute)
		{
			// ��ȡ���ԼĴ���
			CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };

			//��ȡ�߳�������
			if (!GetThreadContext(m_hThre, &ct))
			{
				PutsError("��ȡ�߳�������ʧ��");
				return FALSE;
			}

			//��ȡ Dr7 �ṹ�岢����
			PDR7 Dr7 = (PDR7)& ct.Dr7;

			// ͨ�� Dr7 �е�L(n) ֪����ǰ�ĵ��ԼĴ����Ƿ�ʹ��
			if (ct.Dr0 == i.Address)
			{
				// ����Ӳ���ϵ��Ƿ���Ч
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
				PutsError("��Ӳ���ϵ�ʧ��");
				return false;
			}*/

			//���û�ȥ
			if (!SetThreadContext(m_hThre, &ct)) {
				PutsError("�����߳�������ʧ��");
				return FALSE;
			}
		}

		else if (i.BreakType == Mem&&i.Execute) {
			
				DWORD ret = {};
				//�޸��ڴ�����Ϊ
				if (!VirtualProtectEx(m_hProc, (LPVOID)i.Address, 1, i.MemClas, &ret))
				{
					PutsError("�޸��ڴ��ҳ����ʧ��");

					return FALSE;
				}
				
			
		}
	}
	return TRUE;
}

BOOL Debug::ClearBreak(DWORD c_Address)
{
	// �ж���û�б�ɾ��
	bool eflag = true;
	for (auto& i : m_BreakPointAll)
	{
		// ����жϵ�
		if (i.Address == c_Address)
		{
			i.Execute = FALSE;
			eflag = true;
			printf("�ϵ���ʧЧ\n");
			break;

		}
		else
			eflag = false;
	}
	if (!eflag)
	{
		printf("û���ҵ�����������\n:");
		return FALSE;
	}
	printf("�ϵ���ʧЧ�Ƿ�ɾ��(y/n):");
	getchar();
	char c = 0;
	scanf("%c",&c);
	if(c=='y')
	{
		// ��ʼ������
		std::vector<BreakPoint>::iterator iter = m_BreakPointAll.begin();

		// ��������
		while (iter != m_BreakPointAll.end())
		{
			//�ж��Ƿ���Ҫɾ��
			if(!iter->Execute)
			{
				//���������ϵ�ֱ��ɾ��
				if (iter->BreakType == CcFlag)
				{
					// �Ӷ�̬��������ɾ��
					iter = m_BreakPointAll.erase(iter);
					break;
				}
				//�����Ӳ���ϵ�ͰѼĴ���Ҳ���һ��
				if(iter->BreakType == HdFlag)
				{

						// ��ȡ�����ԼĴ���
						CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
						GetThreadContext(m_hThre, &Context);

						// ��ȡ Dr7 �Ĵ���
						PDR7 Dr7 = (PDR7)& Context.Dr7;

						// �������Ķϵ����ó���Ч��

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
							printf("ɾ��ʧ��û���ҵ�");
							eflag = false;
						}
						if (eflag) {
							// ���޸ĸ��µ��߳�
							if (!SetThreadContext(m_hThre, &Context))
							{
								PutsError("�����߳�������ʧ��");
								break;
							}
							iter = m_BreakPointAll.erase(iter);
							printf("ɾ���ɹ�!\n");
							return TRUE;
						}

						//CloseHandle(l_hThread);
					
				}

				if(iter->BreakType ==Mem)
				{
					//���ж��Ƿ�����һҳ�ڴ��ϲ���ֱ�ӻָ����� ��TF�ϵ�
					
					
					DWORD ret = 0;
					if (!VirtualProtectEx(m_hProc, (LPVOID)iter->Address, 1, iter->OldData, &ret))
					{
						PutsError("ɾ���ڴ�ϵ�ʧ��");
						return FALSE;
					}
					// �Ӷ�̬��������ɾ��
					iter = m_BreakPointAll.erase(iter);
					return TRUE;

				}
			}
			
		}

	}

	return TRUE;
}

