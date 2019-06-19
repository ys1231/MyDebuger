#pragma once
#include<Windows.h>
#include <vector>


// DR7�Ĵ����ṹ��
typedef struct _DR7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// ��������Ч�ռ�
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} DR7, * PDR7;

//��BYTE������	  
enum BreakFlag{ 
	CcFlag,HdFlag,Mem
};

//typedef BOOL(*FUNC)(char* buff);

//��������ϵ�Ľṹ��
typedef struct _BreakPoint {
	DWORD Address;				  //�ϵ��ַ
	DWORD  OldData;				  // �����ǵ����ֽ�(�ڴ�ϵ��� ���ڱ���ɵ�����)
	BreakFlag BreakType = CcFlag; //Ĭ��������ϵ�
	BOOL  Execute = TRUE;		  //�ϵ��Ƿ���Ч
	DWORD MemClas = PAGE_NOACCESS;//�����ڴ�ϵ�ʱʹ��

	//�������ϵ�ʹ�õ�
	BOOL IsCondition = FALSE;

	//�Ƿ��������ϵ� 
	//����������ϵ�  �ж�һ�� �Ƿ��������� ����������� �����û�����(�Ѷϵ�����ΪʧЧ) �����㲻����
	
}BreakPoint,*PBreakPoint;

typedef struct _MyContext{
	DWORD Eax=0;
    DWORD Ecx=0;
	DWORD Edx=0;
	DWORD Ebx=0;
	DWORD Esi=0;
	DWORD Edi=0;
}MyContext,PMyContext;


//�������ṹ��
typedef struct _Plugin{
	
	DWORD serial = 0;		//��� �ڼ������
	char name[100] = {};	//�������
	DWORD func = NULL;		//ָ�����ͺ���ָ��

}Plugin,*PPlugin;

class Debug
{
public:
	Debug();
	~Debug();


public:

	//�����쳣�������һ����Ϣ
	DEBUG_EVENT m_dbgEvent={};

	//���ڷ�����������ϵͳ�Ƿ����ִ�� 
	//˵�� DBG_CONTINUE �Ǽ���ִ�� 
	//DBG_EXCEPTION_NOT_HANDLED ����ǳ����Լ��������쳣��ô��Ӧ�ûָ����
	DWORD m_ReplyInfo = DBG_CONTINUE;

	//�ӵ�����Ϣ�л�ȡ���쳣��Ϣ
	EXCEPTION_RECORD m_ExcepInfo;

	//ͬ���ж��Ƿ���ϵͳ�ϵ� Ĭ�� ��
	BOOL IssystemBp = TRUE;

	//�Ƿ���Ҫ��ʾ��� �ͽ�������  (Ĭ����Ҫ��������Ϣ�ͽ����û�����)
	BOOL IsInputAndShowAsm = TRUE;

	//����Ƿ���Ҫ�ٴ��¶ϵ�
	BOOL IsRepar = FALSE;

	//���ֻ����Ӳ���ϵ�֮���޸�һ�� 
	BOOL IsHPBreak=TRUE;

	//������Լ�����TF
	BOOL IsTF = FALSE;

	//�������ʱ��Ľ��� �߳̾��
	HANDLE m_hProc;//���̾��
	HANDLE m_hThre;//�߳̾��

	//���ڱ����Լ��µ�����ϵ� int3
	std::vector<BreakPoint>m_BreakPointAll;

	//����ִ�������ϵ������ ����
	DWORD IsConDiTion = 0;

	//��ʲô���͵������ϵ�
	DWORD IsConDitionType = 0;

	//�����û����õļĴ���ֵ �����ж��Ƿ���������
	static MyContext m_Myct;

	//�����û���������ĸ��Ĵ���
	static char m_str[10];

	//������Ը��ӵķ�ʽ�� ������ҵ�ID
	DWORD m_iard = 0;

	//�����Խ��̾��
	HANDLE m_hProcess = NULL;

	//������ʲô��ʽ�򿪵�
	BOOL IsOpera = TRUE;

	//��ȡPE�������� ��Ϣ
	char* m_pFile = nullptr;

	//��ȡDOSͷ
	PIMAGE_DOS_HEADER m_pDos;

	//����NTͷ
	PIMAGE_NT_HEADERS m_pNT;


public:

	//1.����Ƿ��ȡ����Ա
	void PrintIcon();	  

	//2.����Ϊ����Ȩ��
	BOOL PromotionDebugPrivilege(BOOL fEnable);	

	//3.���Ե��Եķ�ʽ�򿪽���
	BOOL Open(char FilePath[]);

	BOOL Open(DWORD Pid);

	//4.�ȴ��쳣�¼�����
	VOID WaitForEvent();	

	//5.�����쳣�ж���ʲô�쳣����Ӧ�Ĵ���
	VOID FilterException();

	//6.�����쳣��ʾ�����
	VOID ShowAsm();

	//�ֶ�������ʾ�����
	VOID ShowAsm(DWORD c_Address,DWORD c_Len=10);

	// �޸�ָ����ַ������
	VOID AlterAsm();

	//7.��ȡ�û�������Ϣ
	VOID GetCommand();

	//7.1��ȡ�������
	VOID GetHelp();

	//8.�鿴���еĶϵ�
	VOID FindBreak();

	//�鿴�ڴ�
	VOID ShowMem(DWORD c_Address);

	//�޸��ڴ�����
	VOID AlterMem(DWORD c_Address);

	//�鿴ջ����
	VOID ShowStack(const DWORD Size);

	//�޸ļĴ���
	VOID AlterRegister();

	//����ģ����Ϣ
	VOID GetModuleList();

	//DLLԶ���߳�ע��
	BOOL DllInject();

	//�������뵼����
	VOID Analysis_Export_Import(DWORD c_Address, DWORD c_BaseSize);

	//��ʼ�����
	VOID LoadPlugin();

public:

	// �����ϵ� ����Ӳ���ϵ�
	BOOL SetBreakTF();

	//��������  
	BOOL SetStepTF();

	// ��������ϵ� (�����û�����ĵ�ַ)
	BOOL SetBreakInt3(DWORD c_Address,bool c_Execute=true, bool c_CondiTion =false);

	//(�޸�����ϵ�)+�ж��Ƿ����Լ��µĶϵ� EIP--  
	BOOL ReparBreak();
	
	//����Ӳ���ϵ�   //�¶ϵ�ĵ�ַ     //�ϵ�����    //����1
	BOOL SetBreakHD(DWORD c_Address,DWORD c_Type=0, DWORD c_Len=0);

	//�޸�Ӳ���ϵ�
	BOOL ReparBreakHD();

	//�ڴ�ϵ�
	BOOL SetMemBreak(DWORD c_Address,char str[]);

	//�޸��ڴ�ϵ�
	BOOL ReparMemBreak();

	//�ٴ��¶ϵ�
	BOOL ReparSetBreak();

	//���ݱ������ ��Ч�Ķϵ�
	BOOL ClearBreak(DWORD c_Address);





};

