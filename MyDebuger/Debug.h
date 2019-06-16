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

//�ϵ�����
enum BreakFlag
{
	CcFlag,HdFlag,Mem
};

//��������ϵ�Ľṹ��
typedef struct _BreakPoint {
	DWORD Address;				  //�ϵ��ַ
	DWORD  OldData;				  // �����ǵ����ֽ�(�ڴ�ϵ��� ���ڱ���ɵ�����)
	BreakFlag BreakType = CcFlag; //Ĭ��������ϵ�
	BOOL  Execute = TRUE;		  //�ϵ��Ƿ���Ч
	
}BreakPoint,*PBreakPoint;


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


	////�Ƿ���Ҫ��ʾ��� �ͽ�������  (Ĭ����Ҫ��������Ϣ�ͽ����û�����)
	//BOOL IsInputAndShowAsm = TRUE;

	////����Ƿ���Ҫ�޸��ڴ�ҳ����
	//bool IsSetMen = false;



	//�������ʱ��Ľ��� �߳̾��
	HANDLE m_hProc;//���̾��
	HANDLE m_hThre;//�߳̾��

	//���ڱ����Լ��µ�����ϵ� int3
	std::vector<BreakPoint>m_BreakPointAll;

public:

	//1.����Ƿ��ȡ����Ա
	void PrintIcon();	  

	//2.����Ϊ����Ȩ��
	BOOL PromotionDebugPrivilege(BOOL fEnable);	

	//3.���Ե��Եķ�ʽ�򿪽���
	BOOL Open(char FilePath[]);

	//4.�ȴ��쳣�¼�����
	VOID WaitForEvent();	

	//5.�����쳣�ж���ʲô�쳣����Ӧ�Ĵ���
	VOID FilterException();

	//6.�����쳣��ʾ�����
	VOID ShowAsm();

	//7.��ȡ�û�������Ϣ
	VOID GetCommand();

	//8.�鿴���еĶϵ�
	VOID FindBreak();

	// �޸�ָ����ַ������
	VOID AlterAsm();

public:

	// �����ϵ� ����Ӳ���ϵ�
	BOOL SetBreakTF();

	// ��������ϵ� (�����û�����ĵ�ַ)
	BOOL SetBreakInt3(DWORD c_Address);

	//(�޸�����ϵ�)+�ж��Ƿ����Լ��µĶϵ� EIP--  
	BOOL ReparBreak();
	
	//����Ӳ���ϵ�   //�¶ϵ�ĵ�ַ     //�ϵ�����    //����1
	BOOL SetBreakHD(DWORD c_Address,DWORD c_Type=0, DWORD c_Len=0);

	//�޸�Ӳ���ϵ�
	BOOL ReparBreakHD();

	//�ٴ��¶ϵ�
	BOOL ReparSetBreak();

	//���ݱ������ ��Ч�Ķϵ�
	BOOL ClearBreak(DWORD c_Address);
	
	//����ɾ���ϵ� (�޸ı�־ΪFALSE)
	//BOOL SetBreakEffect(DWORD c_Address);

};

