#include<stdio.h>
#include<windows.h>
#include<shlwapi.h>

#pragma comment(lib,"shlwapi.lib")
typedef struct FILEINFORMATION
{
	HANDLE hFile;
	PCHAR ptrFileName;
	PDWORD ptrFileAddress;
	DWORD dwFilesize;
}FileInfor;
typedef struct OLDPEINFOR
{
	DWORD ImageBase;
	DWORD OEP;
	IMAGE_DATA_DIRECTORY IDT;
	IMAGE_DATA_DIRECTORY IAT;
	IMAGE_DATA_DIRECTORY ROC;
	IMAGE_DATA_DIRECTORY TLS;
}OldPeInfor;

/*加载文件到内存*/
FileInfor LoadFile(char* FileName)
{
	FileInfor myFileInfor;
	myFileInfor.hFile = CreateFileA(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	myFileInfor.dwFilesize = GetFileSize(myFileInfor.hFile, NULL);
	myFileInfor.ptrFileName = PathFindFileNameA(FileName);
	myFileInfor.ptrFileAddress = (PDWORD)malloc(myFileInfor.dwFilesize);
	memset(myFileInfor.ptrFileAddress, 0, myFileInfor.dwFilesize);
	DWORD dwRead = 0;
	ReadFile(myFileInfor.hFile, myFileInfor.ptrFileAddress, myFileInfor.dwFilesize, &dwRead, NULL);

	return myFileInfor;
}
/*按照对齐粒度对齐*/
DWORD SetAlignment(DWORD size, DWORD Alignment)
{
	return size % Alignment == 0 ? size : (size / Alignment + 1) * Alignment;
}
/*获取DOS头*/
PIMAGE_DOS_HEADER GetDosHeader(PDWORD ImageBase)
{
	return PIMAGE_DOS_HEADER(ImageBase);
}
/*获取NT头*/
PIMAGE_NT_HEADERS GetNtHeader(PDWORD ImageBase)
{
	return (PIMAGE_NT_HEADERS)(GetDosHeader(ImageBase)->e_lfanew + (DWORD)ImageBase);
}
/*获取File头*/
PIMAGE_FILE_HEADER GetFileHeader(PDWORD ImageBase)
{
	return (PIMAGE_FILE_HEADER)(&GetNtHeader(ImageBase)->FileHeader);
}
/*获取optional头*/
PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PDWORD ImageBase)
{
	return (PIMAGE_OPTIONAL_HEADER)(&GetNtHeader(ImageBase)->OptionalHeader);
}
/*获取节区*/
PIMAGE_SECTION_HEADER GetSectionHeader(PDWORD ImageBase, char* SectionName)
{
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(GetNtHeader(ImageBase));
	for (int i = 0; i < GetFileHeader(ImageBase)->NumberOfSections; i++)
	{
		if (!memcmp(SectionHeader[i].Name, SectionName, strlen(SectionName) + 1))
			return &SectionHeader[i];
	}
	return nullptr;
}
/*获取函数节区内偏移*/
DWORD GetFunOffset(HMODULE hPackerdll, char* FunctionName)
{
	DWORD  dwstart = (DWORD)GetProcAddress(hPackerdll, FunctionName);
	DWORD dwstartOffset = dwstart - (DWORD)hPackerdll - GetSectionHeader((PDWORD)hPackerdll, ".text")->VirtualAddress;
	return dwstartOffset;
}
/*加密节区*/
FileInfor EncrpytSection(FileInfor myFileInfor)
{
	PDWORD StartAddr = (PDWORD)((DWORD)myFileInfor.ptrFileAddress + GetSectionHeader(myFileInfor.ptrFileAddress, ".text")->PointerToRawData);
	PDWORD EndAddr = (PDWORD)((DWORD)StartAddr + GetSectionHeader(myFileInfor.ptrFileAddress, ".text")->SizeOfRawData);

	while (StartAddr < EndAddr)
	{

		*StartAddr ^= 0x11223344;
		StartAddr++;
	}
	return myFileInfor;
}
/*复制壳区段头信息*/
FileInfor CopySectionHeader(FileInfor myFileInfor, PDWORD DllBase, char* NewSectionName, char* SrcSectionName)
{
	PIMAGE_SECTION_HEADER LastSectionHeader = &IMAGE_FIRST_SECTION(GetNtHeader(myFileInfor.ptrFileAddress))[GetFileHeader(myFileInfor.ptrFileAddress)->NumberOfSections - 1];
	GetFileHeader(myFileInfor.ptrFileAddress)->NumberOfSections += 1;
	PIMAGE_SECTION_HEADER NewSectionHeader = LastSectionHeader + 1;
	memset(NewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	PIMAGE_SECTION_HEADER SrcSectionHeader = GetSectionHeader(DllBase, SrcSectionName);
	memcpy(NewSectionHeader, SrcSectionHeader, sizeof(IMAGE_SECTION_HEADER));
	memcpy(NewSectionHeader->Name, NewSectionName, strlen(NewSectionName)+1);
	NewSectionHeader->VirtualAddress = LastSectionHeader->VirtualAddress + SetAlignment(LastSectionHeader->Misc.VirtualSize, GetOptionalHeader(myFileInfor.ptrFileAddress)->SectionAlignment);
	NewSectionHeader->Misc.VirtualSize = SrcSectionHeader->Misc.VirtualSize;//memcpy已经将整个sectionheader拷贝过了
	NewSectionHeader->PointerToRawData = LastSectionHeader->PointerToRawData + SetAlignment(LastSectionHeader->SizeOfRawData, GetOptionalHeader(myFileInfor.ptrFileAddress)->FileAlignment);
	NewSectionHeader->SizeOfRawData = SetAlignment(SrcSectionHeader->Misc.VirtualSize, GetOptionalHeader(myFileInfor.ptrFileAddress)->FileAlignment);
	NewSectionHeader->Characteristics = SrcSectionHeader->Characteristics;//memcpy已经将整个sectionheader拷贝过了

	GetOptionalHeader(myFileInfor.ptrFileAddress)->SizeOfImage += SetAlignment(NewSectionHeader->Misc.VirtualSize, GetOptionalHeader(myFileInfor.ptrFileAddress)->SectionAlignment);

	return myFileInfor;
}
/*复制壳区段信息*/
FileInfor CopySection(FileInfor myFileInfor, PDWORD DllBase, char* NewSectionName, char* SrcSectionName)
{
	BYTE* SrcData = (BYTE*)(GetSectionHeader(DllBase, SrcSectionName)->VirtualAddress + (DWORD)DllBase);
	DWORD SrcDataSize = GetSectionHeader(DllBase, SrcSectionName)->SizeOfRawData;
	DWORD  Ailgment= SetAlignment(SrcDataSize, GetOptionalHeader(myFileInfor.ptrFileAddress)->FileAlignment);//当文件对齐粒度不是默认200时就需要对齐了
	PDWORD NewFileAddress = (PDWORD)malloc(myFileInfor.dwFilesize + Ailgment);
	memset(NewFileAddress,0, myFileInfor.dwFilesize + Ailgment);//0填充
	memcpy(NewFileAddress, myFileInfor.ptrFileAddress, myFileInfor.dwFilesize);
	memcpy((PDWORD)((DWORD)NewFileAddress + myFileInfor.dwFilesize), SrcData, SrcDataSize);
	free(myFileInfor.ptrFileAddress);
	myFileInfor.ptrFileAddress = NewFileAddress;
	myFileInfor.dwFilesize += Ailgment;
	return myFileInfor;
}
VOID SetNewOEP(PDWORD FileAddress, DWORD dwStartOffset)
{
	GetOptionalHeader(FileAddress)->AddressOfEntryPoint = GetSectionHeader(FileAddress, ".yean")->VirtualAddress + dwStartOffset;
}
/*保存到文件*/
BOOL SaveToFile(FileInfor myFileInfor)
{
	char FileName[MAX_PATH] = {0};
	for (int i = 0; i < strlen(myFileInfor.ptrFileName); i++)
	{
		if (myFileInfor.ptrFileName[i] == '.')
		{
			FileName[i] = '_';
			for (i; i < strlen(myFileInfor.ptrFileName); i++)
			{
				FileName[i + 1] = myFileInfor.ptrFileName[i];
			}
			break;
		}
		FileName[i] = myFileInfor.ptrFileName[i];
	}

	HANDLE hFile = CreateFile(FileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
	DWORD dwWrite = NULL;

	WriteFile(hFile, myFileInfor.ptrFileAddress, myFileInfor.dwFilesize, &dwWrite, NULL);
	// 写完以后关闭句柄并且释放空间
	CloseHandle(hFile);
	CloseHandle(myFileInfor.hFile);
	free(myFileInfor.ptrFileAddress);
	return TRUE;
}
/*保存并清除重定位、IAT、导出表等信息*/
OLDPEINFOR  GetPeInfor(FileInfor myFileInfor)
{
	OldPeInfor OldPeInfo;

	OldPeInfo.IDT.VirtualAddress = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	OldPeInfo.IDT.Size = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	OldPeInfo.ROC.VirtualAddress = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	OldPeInfo.ROC.Size = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

	OldPeInfo.TLS.VirtualAddress = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	OldPeInfo.TLS.Size = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;

	OldPeInfo.IAT.VirtualAddress = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	OldPeInfo.IAT.Size = GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	GetOptionalHeader(myFileInfor.ptrFileAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	
	OldPeInfo.ImageBase = GetOptionalHeader(myFileInfor.ptrFileAddress)->ImageBase;
	OldPeInfo.OEP = GetOptionalHeader(myFileInfor.ptrFileAddress)->AddressOfEntryPoint;
	return OldPeInfo;
}
/*保存IAT、导出表等信息到文件*/
VOID SavePeInfo(FileInfor myFileInfor,OLDPEINFOR OldPeInfo)
{
	PIMAGE_SECTION_HEADER LastSectionHeader = &IMAGE_FIRST_SECTION(GetNtHeader(myFileInfor.ptrFileAddress))[GetFileHeader(myFileInfor.ptrFileAddress)->NumberOfSections - 1];
	OldPeInfor *mem = (OldPeInfor *)(LastSectionHeader + 1);//利用PE空余空间写入原始文件信息
	*mem = OldPeInfo;
}