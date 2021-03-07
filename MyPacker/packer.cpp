#include "packer.h"

int main()
{

	printf("输入要加壳的程序路径:");
	char FilePath[MAX_PATH] = {};
	scanf_s("%s", FilePath, MAX_PATH);
	//读取文件到内存
	FileInfor myFileInfor = LoadFile(FilePath);
	//加载壳dll
	HMODULE hPackerdll = LoadLibraryA("PackerCode.dll");
	//获取shellcode节区内偏移
	DWORD  dwstartOffset = GetFunOffset(hPackerdll, "start");
	//获取并清除IAT,重定位等必要信息
	OldPeInfor OldPeInfo = GetPeInfor(myFileInfor);
	//加密节区
	myFileInfor = EncrpytSection(myFileInfor);
	//复制壳区段头信息
	myFileInfor = CopySectionHeader(myFileInfor, (PDWORD)hPackerdll, ".yean", ".text");
	//复制壳区段内容
	myFileInfor = CopySection(myFileInfor, (PDWORD)hPackerdll, ".yean", ".text");
	//保存IAT，IDT等信息到文件
	SavePeInfo(myFileInfor,OldPeInfo);
	//设置新的OEP
	SetNewOEP(myFileInfor.ptrFileAddress, dwstartOffset);
	//保存到文件
	SaveToFile(myFileInfor);
	return 0;
}