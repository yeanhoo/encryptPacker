#include<stdio.h>
#include<windows.h>
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

typedef BOOL(WINAPI* M_VirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef HMODULE(WINAPI* M_GetModuleHandleA)(
	_In_opt_ LPCSTR lpModuleName
	);

typedef HMODULE(WINAPI* M_LoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

typedef FARPROC(WINAPI* M_GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);

typedef LPVOID(WINAPI* M_VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD flAllocationType,
	_In_     DWORD flProtect
	);
typedef LPVOID(WINAPI* M_memcpy)(
	_In_reads_bytes_(_Size) void const* _Buf1,
	_In_reads_bytes_(_Size) void const* _Buf2,
	_In_                    size_t      _Size
	);

typedef struct OLDPEINFOR
{
	DWORD ImageBase;
	DWORD OEP;
	IMAGE_DATA_DIRECTORY IDT;
	IMAGE_DATA_DIRECTORY IAT;
	IMAGE_DATA_DIRECTORY ROC;
	IMAGE_DATA_DIRECTORY TLS;
}OldPeInfor;
struct TypeOffset
{
	WORD Offset : 12;//机构内位域的定义
	WORD Type : 4;
};

extern "C" {
	/*shellcode查找kernel32地址*/
	__declspec(naked) PDWORD GerKernelBase()
	{
		__asm
		{
			mov eax, fs: [0x30] ;
			mov eax, [eax + 0x0c];
			mov eax, [eax + 0x14];
			mov eax, [eax];
			mov eax, [eax];
			mov eax, [eax + 0x10];
			ret
		}


	}
	/*通过函数名称遍历导出表查找导出函数*/
	DWORD GetFunAddr(DWORD* DllBase, char* FunName)
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)pDos);
		PIMAGE_OPTIONAL_HEADER pOt = (PIMAGE_OPTIONAL_HEADER)&pNt->OptionalHeader;
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pOt->DataDirectory[0].VirtualAddress + (DWORD)DllBase);

		PDWORD pNameAddr = (PDWORD)(pExport->AddressOfNames + (DWORD)DllBase);
		PWORD pNameOrdAddr = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)DllBase);
		PDWORD pFunAddr = (PDWORD)(pExport->AddressOfFunctions + (DWORD)DllBase);
		for (int i = 0; i < pExport->NumberOfNames; i++)
		{
			char* Name = (char*)(pNameAddr[i] + (DWORD)DllBase);
			if (!strcmp(Name, FunName))
			{
				WORD NameOrdinal = pNameOrdAddr[i];
				return pFunAddr[NameOrdinal] + (DWORD)DllBase;
			}
		}
	}
	/*获取指定函数地址*/
	FARPROC  GetApi(char* LibraryName, char* FuncName)
	{
		PDWORD KernerBase = GerKernelBase();
		char GetPro[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
		char Libry[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
		M_GetProcAddress MyGetProcess = (M_GetProcAddress)GetFunAddr(KernerBase, GetPro);
		M_LoadLibraryA MyLoadLibraryA = (M_LoadLibraryA)GetFunAddr(KernerBase, Libry);
		return MyGetProcess(MyLoadLibraryA(LibraryName), FuncName);
	}
	/*获取当前模块ImageBase*/
	__declspec(naked) PDWORD GetModuleBase()
	{
		__asm
		{
			mov eax, fs: [0x30] ;
			mov eax, [eax + 0x8];
			ret;
		}
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
	/*获取节区*/
	PIMAGE_SECTION_HEADER GetSectionHeader(PDWORD ImageBase, char* SectionName)
	{
		PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(GetNtHeader(ImageBase));
		for (int i = 0; i < GetFileHeader(ImageBase)->NumberOfSections; i++)
		{
			char Vcrun[] = { 'v','c','r','u','n','t','i','m','e','1','4','0','.','d','l','l','\0' };
			char myMemcmp[] = { 'm','e','m','c','m','p','\0' };
			M_memcpy Mymemcpy = (M_memcpy)GetApi(Vcrun, myMemcmp);
			if (!Mymemcpy(SectionHeader[i].Name, SectionName, strlen(SectionName) + 1))
				return &SectionHeader[i];
		}
		return nullptr;
	}
	/*获取修复PE必要信息*/
	OldPeInfor GetOldPEInfor()
	{
		/*获取当前模块基址*/
		PDWORD ImageBase = GetModuleBase();
		PIMAGE_SECTION_HEADER LastSectionHeader = &(IMAGE_FIRST_SECTION(GetNtHeader(ImageBase))[GetFileHeader(ImageBase)->NumberOfSections]);//直接指向sectionHeader末尾
		return *(OldPeInfor *)LastSectionHeader;
	}
	BOOL IsDebug()
	{
		
		
		return TRUE;

	}
	/*IAT hook*/
	DWORD HookIAT(DWORD func)
	{
		char shellcode[] = { 
			0x33,0xc0,						//xor eax,eax
			0x85,0xc0,						//test eax,eax
			0x74,0x03,						//je 03
			0x75,0x01,						//jnz 01
			0xe8,0xB8,0x11,0x11,0x11,0x11,  //mov eax,11111111
			0xFF,0xE0						//jmp eax
		};
		char Kernel[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
		char Virall[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
		M_VirtualAlloc MyVirtualAlloc = (M_VirtualAlloc)GetApi(Kernel, Virall);
		char* pBuff = (char*)MyVirtualAlloc(0, 0x20, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(pBuff, shellcode, sizeof(shellcode));//测试时，这里memcpy被编译成多个mov指令
		// 写入真正的函数
		*(DWORD*)&pBuff[10] = func;

		return (DWORD)pBuff;
	}
	/*解密节区*/
	BOOL DecryptCode()
	{
		char Kernel[] = {'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
		char Virprot[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
		char SecName[] = {'.','t','e','x','t','\0'};

		M_VirtualProtect MyVirtualProtect = (M_VirtualProtect)GetApi(Kernel, Virprot);
		DWORD dwOldProtect = 0;
		PDWORD ImageBase = GetModuleBase();
		DWORD SectionAddr = GetSectionHeader(ImageBase, SecName)->VirtualAddress;
		DWORD SectionSize = GetSectionHeader(ImageBase, SecName)->SizeOfRawData;
		
		PDWORD StartAddr = (PDWORD)((DWORD)ImageBase + SectionAddr);
		PDWORD EndAddr = (PDWORD)((DWORD)StartAddr + SectionSize);
		MyVirtualProtect(StartAddr, SectionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);

		PDWORD StartBack = StartAddr;
		while (StartAddr < EndAddr)
		{

			*StartAddr ^= 0x11223344;
			StartAddr++;
		}

		MyVirtualProtect(StartBack, SectionSize, dwOldProtect, &dwOldProtect);
		return TRUE;
	}
	/*修正PE头*/
	VOID  FixPEFile()
	{
		/*获取修复PE必要信息*/
		OldPeInfor oldPEinfo = GetOldPEInfor();
		DWORD dwBase = (DWORD)GetModuleBase();
		/*获取必要函数地址*/
		char Kernel[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
		char Virprot[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
		char Libry[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
		PDWORD KernerBase = GerKernelBase();
		M_VirtualProtect MyVirtualProtect = (M_VirtualProtect)GetApi(Kernel, Virprot);
		M_LoadLibraryA MyLoadLibraryA = (M_LoadLibraryA)GetFunAddr(KernerBase, Libry);
		DWORD dwOldProtect = 0;//保存内存页属性
		/*修正IAT*/
		PIMAGE_IMPORT_DESCRIPTOR IID = (PIMAGE_IMPORT_DESCRIPTOR)(dwBase + oldPEinfo.IDT.VirtualAddress);
		if (oldPEinfo.IDT.VirtualAddress)
		{
			while (IID->Name)
			{
				char* DllName = (char*)(IID->Name + dwBase);
				/*遍历导入表*/

				HMODULE hModul = MyLoadLibraryA(DllName);
				PDWORD ptrINT = (PDWORD)(IID->OriginalFirstThunk + dwBase);//IMAGE_THUNK_DATA32
				PDWORD ptrIAT = (PDWORD)(IID->FirstThunk + dwBase);//IMAGE_THUNK_DATA32
				int num = 0;
				while (*ptrINT)
				{
					LPVOID Func;
					if (*ptrINT & 0x80000000)//最高位为1,序号导入函数
					{

						DWORD Order = (*ptrINT) & 0xFFFF;//序号
						Func = GetApi(DllName, (char*)Order);
					}
					else//最高位为0, 函数名称导入
					{
						PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)(*ptrINT + dwBase);//Image_Import_By_Name
						Func = GetApi(DllName, (char*)FuncName->Name);
					}
					num++;
					MyVirtualProtect(ptrIAT, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
					if(num%10 == 0)
					{
						((PIMAGE_THUNK_DATA)ptrIAT)->u1.Function = HookIAT((DWORD)Func);//hook部分IAT
					}
					else
					{
						((PIMAGE_THUNK_DATA)ptrIAT)->u1.Function = (DWORD)Func;
					}
					
					MyVirtualProtect(ptrIAT, 4, dwOldProtect, &dwOldProtect);
					ptrINT++;
					ptrIAT++;
				}
				IID++;
			}
		}

		/*修正重定位*/
		PIMAGE_BASE_RELOCATION RelocTable = (PIMAGE_BASE_RELOCATION)(oldPEinfo.ROC.VirtualAddress + dwBase);
		if ( (oldPEinfo.ROC.VirtualAddress) && (dwBase != oldPEinfo.ImageBase))
		{
			while (RelocTable->SizeOfBlock)
			{
				// 如果重定位的数据在代码段，就需要修改访问属性
				MyVirtualProtect((LPVOID)(RelocTable->VirtualAddress + dwBase), 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				int nCount = (RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(TypeOffset);//typeOffset为计数器
				TypeOffset* to = (TypeOffset*)(RelocTable + 1);//Reloc+1 = TypeOffset
				for (int i = 0; i < nCount; ++i)
				{
					// 如果type的值为3，则需要重定位
					if (to[i].Type == 3)
					{
						// 获取到需要重定位的地址所在的位置,基址+段偏移+页偏移
						DWORD* addr = (DWORD*)(dwBase + RelocTable->VirtualAddress + to[i].Offset);
						// 计算重定位后的地址
						*addr = *addr - oldPEinfo.ImageBase + dwBase;
					}
				}
				// 还原区段的保护属性
				MyVirtualProtect((LPVOID)(RelocTable->VirtualAddress + dwBase), 0x1000, dwOldProtect, &dwOldProtect);
				// 找到下一个重定位块
				RelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)RelocTable + RelocTable->SizeOfBlock);
			}
		}

		/*修正TLS*/
		DWORD oep = dwBase + oldPEinfo.OEP;
		if (!oldPEinfo.TLS.VirtualAddress)
		{
			__asm 
			{
				jmp oep;
			}
		}
		PIMAGE_OPTIONAL_HEADER32 pOpt = (PIMAGE_OPTIONAL_HEADER32) & (GetNtHeader((PDWORD)dwBase)->OptionalHeader);
		PIMAGE_TLS_DIRECTORY ptrTLS = (PIMAGE_TLS_DIRECTORY)(dwBase + oldPEinfo.TLS.VirtualAddress);
		PIMAGE_TLS_CALLBACK* TLSCallback = (PIMAGE_TLS_CALLBACK*)(ptrTLS->AddressOfCallBacks - oldPEinfo.ImageBase +dwBase);//这里不需要加基址
		while (*TLSCallback)
		{
			(*TLSCallback)((PVOID)dwBase,DLL_PROCESS_ATTACH,NULL);
			TLSCallback++;
		}
		__asm
		{
			jmp oep;
		}
	}

}
