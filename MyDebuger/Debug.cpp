#include "Debug.h"
#include <ShlObj_core.h>
#include <cstdio>
#include "debugRegisters.h"
#include <iostream>

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
#pragma comment(lib,"BeaEngine_4.1/Win32/Lib/BeaEngine.lib")



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
	//PrintIcon();
	//PromotionDebugPrivilege(TRUE);
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
	else
		MessageBoxW(0, L"Admin", L"��ʾ", 0);

}

//����Ϊ����Ȩ��
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
	//���մ������̵���Ϣ
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = { 0 };

	//�Ե��Է�ʽ����һ������
	BOOL ret = CreateProcess(FilePath,NULL,NULL,NULL,FALSE,
		DEBUG_ONLY_THIS_PROCESS| CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);

	//����ʧ�ܷ��ؼ�
	if(!ret)
	{
		return FALSE;
	}


	return TRUE;
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


		//�ٰѶϵ�����ȥ
		ReparSetBreak();


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
		//�����ϵ� int3 //������Լ�������һ��
	case EXCEPTION_BREAKPOINT:

		//�ж��Ƿ���ϵͳ�ϵ�
		if(IssystemBp)
		{
			IssystemBp = false;
			printf("����ϵͳ�ϵ�:%08X\n",(DWORD)m_ExcepInfo.ExceptionAddress);
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
		//ȷ���Ƿ��������Լ��µĶϵ� 
		//�޸ļĴ���Ϊ��ִ�д˶ϵ�

			ReparBreakHD();

		break;
	}
		//����û��Ȩ�޵������ַ �ڴ�ϵ�
	case EXCEPTION_ACCESS_VIOLATION:


		break;
	default:
		m_ReplyInfo = DBG_EXCEPTION_NOT_HANDLED;
		break;
	}

		//��ʾ�����
		ShowAsm();

		//�ȴ��û�����
		GetCommand();

	return ;
}

VOID Debug::ShowAsm()
{

	//��ʾ�Ĵ�����Ϣ
	CONTEXT ct = {};

	//��ȡȫ���Ĵ�����Ϣ
	ct.ContextFlags = CONTEXT_ALL;

	GetThreadContext(m_hThre, &ct);

	//�������ʾ����
	printf("-----------------------------------------------------\n");
	printf("|Eax:%08X Ecx:%08X Edx:%08X Ebx:%08X|\n", ct.Eax, ct.Ecx, ct.Edx, ct.Ebx);
	printf("|Esp:%08X Ebp:%08X Esi:%08X Edi:%08X|\n",ct.Esp,ct.Ebp,ct.Esi,ct.Edi);
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
		printf("%*c", 20 - nLen * 2, ' ');

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
			break;
		}
		else if (!_stricmp("bp", cmd))	//�����ϵ�
		{

			scanf("%X",&Address);		//�����û������ַ

			SetBreakInt3(Address);		//���뺯����ʼ�������ϵ�
		}
		else if(!_stricmp("hp", cmd))	//Ӳ���ϵ�
		{
			
			scanf("%X%s", &Address, str);

			// �����û��������öϵ�����  printf("1�ֽ�:0|2�ֽ�:1|4�ֽ�:3");
			if (!_stricmp(str, "-x")) {
				c_Type = 0; c_Len = 0;
			}else if(!_stricmp(str, "-r"))
			{
				c_Type = 3; scanf("%d", &c_Len);
			}
			else if (!_stricmp(str, "-w"))
			{
				c_Type = 1; scanf("%d", &c_Len);
			}
			else {
				printf("Input Error\n");
				printf(">");
				continue;
			}
			SetBreakHD(Address,c_Type,c_Len);
		}
		else if(!_stricmp("fp", cmd))
		{
			//�鿴���жϵ�
			FindBreak();
		}
		else if(!_stricmp("dp",cmd))
		{
			scanf("%X",&Address);
			ClearBreak(Address);
		}
		else if(!_stricmp("xasm",cmd))
		{
			AlterAsm();
		}
		else if (!_stricmp("g", cmd)) {
			break;
		}
		else if(!_stricmp("cls",cmd))
		{
			system("cls");
		}
		else
			printf("Input Error\n");

		printf(">");
		
		
	}


	return;
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
		case 0:strcpy(pType, "�����ϵ�");
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

		if (!strcmp(xed.instr,"0"))
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

		//д��CC �������ϵ�
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

// ����int3
BOOL Debug::SetBreakInt3(DWORD c_Address)
{

	for(auto&i:m_BreakPointAll)
	{
		if(i.Address==c_Address)
		{
			i.Execute = TRUE;
			return TRUE;
		}
	}

	//����ϵ���Ϣ 
	BreakPoint bp ={c_Address,0,CcFlag ,TRUE};

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

	//д��CC �������ϵ�
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

			return TRUE;
		}

		

	}


	return TRUE;
}

BOOL Debug::SetBreakHD(DWORD c_Address, DWORD c_Type, DWORD c_Len)
{
	// ���ԼĴ��� Dr0-DR7 

	// ���ڱ���ԭ���ڴ������
	BreakPoint HdInfo = { c_Address,0,HdFlag,TRUE};

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
		PutsError("��Ӳ���ϵ�ʧ��");
		return false;
	}

	//���û�ȥ
	if (!SetThreadContext(m_hThre, &ct)) {
		PutsError("�����߳�������ʧ��");
		return FALSE;
	}

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
			
		/*	switch ()
		{
		case 1: {

			i.Execute = TRUE;
			Dr7->L0 = 0;
			break; 
		}
		case 2: {
			Dr7->L1 = 0;
			i.Execute = TRUE;
			break;
		}
		case 4: {
			Dr7->L2 = 0;
			i.Execute = TRUE;
			break;
		}
		case 8: {
			Dr7->L3 = 0;
			i.Execute = TRUE;
			break;
		}
		}*/

		// ���޸ĸ��µ��߳�
		if (!SetThreadContext(m_hThre, &Context))
		{
			PutsError("�����߳�������ʧ��");

		}

		//CloseHandle(l_hThread);
		}
	}

	return 1;
}

BOOL Debug::ReparSetBreak()
{

	for (auto& i : m_BreakPointAll)
	{
		// ����������ϵ�Ͱ�\xCCд��ȥ
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

			//д��CC �������ϵ�
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
			printf("ɾ���ɹ�\n");
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
	printf("�ϵ���ʧЧ�Ƿ���(y/n):");
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
				//����������ϵ�ֱ��ɾ��
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
						}

						//CloseHandle(l_hThread);
					
				}
			}

		}

	}

	return TRUE;
}
