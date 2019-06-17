
#include"Debug.h"

int main()
{
	char FilePath[MAX_PATH] ="../Release/test.exe";
	Debug dbg;
	if(!dbg.Open(FilePath))
	{
		return 0;
	}
	dbg.WaitForEvent();
	system("pause");
	return 0;
}

