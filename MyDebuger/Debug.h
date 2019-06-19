#pragma once
#include<Windows.h>
#include <vector>


// DR7寄存器结构体
typedef struct _DR7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} DR7, * PDR7;

//断BYTE点类型	  
enum BreakFlag{ 
	CcFlag,HdFlag,Mem
};

//typedef BOOL(*FUNC)(char* buff);

//保存软件断点的结构体
typedef struct _BreakPoint {
	DWORD Address;				  //断点地址
	DWORD  OldData;				  // 被覆盖调的字节(内存断点是 用于保存旧的属性)
	BreakFlag BreakType = CcFlag; //默认是软件断点
	BOOL  Execute = TRUE;		  //断点是否生效
	DWORD MemClas = PAGE_NOACCESS;//设置内存断点时使用

	//给条件断点使用的
	BOOL IsCondition = FALSE;

	//是否是条件断点 
	//如果是条件断点  判断一下 是否满足条件 如果满足条件 接收用户输入(把断点设置为失效) 不满足不接收
	
}BreakPoint,*PBreakPoint;

typedef struct _MyContext{
	DWORD Eax=0;
    DWORD Ecx=0;
	DWORD Edx=0;
	DWORD Ebx=0;
	DWORD Esi=0;
	DWORD Edi=0;
}MyContext,PMyContext;


//保存插件结构体
typedef struct _Plugin{
	
	DWORD serial = 0;		//序号 第几个插件
	char name[100] = {};	//插件名称
	DWORD func = NULL;		//指定类型函数指针

}Plugin,*PPlugin;

class Debug
{
public:
	Debug();
	~Debug();


public:

	//产生异常保存调试一次信息
	DEBUG_EVENT m_dbgEvent={};

	//用于反馈给调试子系统是否继续执行 
	//说明 DBG_CONTINUE 是继续执行 
	//DBG_EXCEPTION_NOT_HANDLED 如果是程序自己产生的异常那么就应该恢复这个
	DWORD m_ReplyInfo = DBG_CONTINUE;

	//从调试信息中获取的异常信息
	EXCEPTION_RECORD m_ExcepInfo;

	//同于判断是否是系统断点 默认 是
	BOOL IssystemBp = TRUE;

	//是否需要显示汇编 和接收输入  (默认需要输出汇编信息和接收用户输入)
	BOOL IsInputAndShowAsm = TRUE;

	//标记是否需要再次下断点
	BOOL IsRepar = FALSE;

	//标记只在下硬件断点之后修复一次 
	BOOL IsHPBreak=TRUE;

	//标记我自己按了TF
	BOOL IsTF = FALSE;

	//保存调试时间的进程 线程句柄
	HANDLE m_hProc;//进程句柄
	HANDLE m_hThre;//线程句柄

	//用于保存自己下的软件断点 int3
	std::vector<BreakPoint>m_BreakPointAll;

	//设置执行条件断点所需的 数据
	DWORD IsConDiTion = 0;

	//是什么类型的条件断点
	DWORD IsConDitionType = 0;

	//保存用户设置的寄存器值 用于判断是否满足条件
	static MyContext m_Myct;

	//保存用户输入的是哪个寄存器
	static char m_str[10];

	//如果是以附加的方式打开 这就是我的ID
	DWORD m_iard = 0;

	//被调试进程句柄
	HANDLE m_hProcess = NULL;

	//我是以什么方式打开的
	BOOL IsOpera = TRUE;

	//获取PE导出导入 信息
	char* m_pFile = nullptr;

	//获取DOS头
	PIMAGE_DOS_HEADER m_pDos;

	//保存NT头
	PIMAGE_NT_HEADERS m_pNT;


public:

	//1.检查是否获取管理员
	void PrintIcon();	  

	//2.提升为调试权限
	BOOL PromotionDebugPrivilege(BOOL fEnable);	

	//3.打开以调试的方式打开进程
	BOOL Open(char FilePath[]);

	BOOL Open(DWORD Pid);

	//4.等待异常事件产生
	VOID WaitForEvent();	

	//5.过滤异常判断是什么异常做相应的处理
	VOID FilterException();

	//6.触发异常显示反汇编
	VOID ShowAsm();

	//手动调用显示反汇编
	VOID ShowAsm(DWORD c_Address,DWORD c_Len=10);

	// 修改指定地址汇编代码
	VOID AlterAsm();

	//7.获取用户输入信息
	VOID GetCommand();

	//7.1获取命令帮助
	VOID GetHelp();

	//8.查看已有的断点
	VOID FindBreak();

	//查看内存
	VOID ShowMem(DWORD c_Address);

	//修改内存数据
	VOID AlterMem(DWORD c_Address);

	//查看栈数据
	VOID ShowStack(const DWORD Size);

	//修改寄存器
	VOID AlterRegister();

	//遍历模块信息
	VOID GetModuleList();

	//DLL远程线程注入
	BOOL DllInject();

	//解析导入导出表
	VOID Analysis_Export_Import(DWORD c_Address, DWORD c_BaseSize);

	//初始化插件
	VOID LoadPlugin();

public:

	// 单步断点 属于硬件断点
	BOOL SetBreakTF();

	//单步不过  
	BOOL SetStepTF();

	// 设置软件断点 (接收用户输入的地址)
	BOOL SetBreakInt3(DWORD c_Address,bool c_Execute=true, bool c_CondiTion =false);

	//(修复软件断点)+判断是否是自己下的断点 EIP--  
	BOOL ReparBreak();
	
	//设置硬件断点   //下断点的地址     //断点类型    //长度1
	BOOL SetBreakHD(DWORD c_Address,DWORD c_Type=0, DWORD c_Len=0);

	//修复硬件断点
	BOOL ReparBreakHD();

	//内存断点
	BOOL SetMemBreak(DWORD c_Address,char str[]);

	//修复内存断点
	BOOL ReparMemBreak();

	//再次下断点
	BOOL ReparSetBreak();

	//根据标记清理 无效的断点
	BOOL ClearBreak(DWORD c_Address);





};

