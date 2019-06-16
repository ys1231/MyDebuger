// strncmp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<string.h>


int main()
{

	const char *str = "hello world";

	const char* str1 = "hello 15pb";

	int a = strncmp(str, str1, 7);
	
		printf("%d",a);
	
   
}
