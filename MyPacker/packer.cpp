#include "packer.h"

int main()
{

	printf("����Ҫ�ӿǵĳ���·��:");
	char FilePath[MAX_PATH] = {};
	scanf_s("%s", FilePath, MAX_PATH);
	//��ȡ�ļ����ڴ�
	FileInfor myFileInfor = LoadFile(FilePath);
	//���ؿ�dll
	HMODULE hPackerdll = LoadLibraryA("PackerCode.dll");
	//��ȡshellcode������ƫ��
	DWORD  dwstartOffset = GetFunOffset(hPackerdll, "start");
	//��ȡ�����IAT,�ض�λ�ȱ�Ҫ��Ϣ
	OldPeInfor OldPeInfo = GetPeInfor(myFileInfor);
	//���ܽ���
	myFileInfor = EncrpytSection(myFileInfor);
	//���ƿ�����ͷ��Ϣ
	myFileInfor = CopySectionHeader(myFileInfor, (PDWORD)hPackerdll, ".yean", ".text");
	//���ƿ���������
	myFileInfor = CopySection(myFileInfor, (PDWORD)hPackerdll, ".yean", ".text");
	//����IAT��IDT����Ϣ���ļ�
	SavePeInfo(myFileInfor,OldPeInfo);
	//�����µ�OEP
	SetNewOEP(myFileInfor.ptrFileAddress, dwstartOffset);
	//���浽�ļ�
	SaveToFile(myFileInfor);
	return 0;
}