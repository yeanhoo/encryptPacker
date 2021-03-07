// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "PackerCode.h"

extern "C"
{
	__declspec(dllexport) __declspec(naked)  void start()
	{
		/*混淆*/
		__asm
		{
			xor eax, eax;
			test eax, eax;
			jz _yeanhoo;
			jnz _yeanhoo;
			__emit(0xE8);

		_yeanhoo:
			xor eax, 1;
			add eax, 2;

		}
		/*虚拟机检测*/
		IsDebug();
		
		/*解密节区*/
		DecryptCode();
		/*修正PE头*/
		FixPEFile();
		
	}
}