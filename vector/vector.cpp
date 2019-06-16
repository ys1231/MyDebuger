// vector.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <vector>

typedef struct _aaa{
	int a = 0;
	bool eflag = false;
}aaa;

int main()
{
	std::vector<aaa>arr;
	std::vector<aaa>::iterator iter;
	aaa a[5];

	a[0].a = 1;
	a[0].eflag = true;
	a[1].a = 2;
	a[1].eflag = true;
	a[2].a = 3;
	a[2].eflag = true;
	a[3].a = 4;
	a[3].eflag = false;
	a[4].a = 5;
	a[4].eflag = true;

	for(int i=0;i<5;i++)
	{
		arr.push_back(a[i]);
		
	}


	for(iter =arr.begin();iter!=arr.end();iter++)
	{
		if(!iter->eflag)
		{
			iter=arr.erase(iter);
		
		}
	
	}


	

	return 0;
}

