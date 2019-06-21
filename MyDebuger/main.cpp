
#include"Debug.h"

int main(){

	printf("1.打开进程|2.以附加的方式进行调试\n:");
	DWORD iard = 0;
	scanf("%d", & iard);

	Debug dbg;

	

	if (iard==1) {

		char FilePath[MAX_PATH] ={};

		scanf("%s",FilePath);

		if (!dbg.Open(FilePath))
		{
			return 0;
		}
		/*DWORD Address =(DWORD)GetModuleHandleA("测试程序.exe");
		printf("%X", Address);*/
	}else
	{
		printf(":");
		scanf("%d", &iard);
		dbg.Open(iard);
	}

	dbg.WaitForEvent();
	system("pause");
	return 0;
}

