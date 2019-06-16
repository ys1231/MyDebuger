
#include"Debug.h"

int main()
{
	char FilePath[MAX_PATH] ="../Release/test.exe";
	Debug dbg;
	dbg.Open(FilePath);
	dbg.WaitForEvent();
	system("pause");
	return 0;
}










