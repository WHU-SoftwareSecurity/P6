#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <tuple>
#include "utils.hpp"


// ʣ�µ�����
// 1. ����½�


// �ٶ� PE �ļ�ͷ�Ĵ�С������ 4096 ���ֽ�
#define MAX_HEADER_LENGTH 4096

enum PEType {
	PE32, PE64
};

typedef struct _PEHeader {
	// mz �ļ�ͷ
	IMAGE_DOS_HEADER mz_header;
	// 64 λ�� 32 λĳЩ�ֶεĳ��Ȳ�һ�������� ImageBase
	// ���� union
	union
	{
		IMAGE_NT_HEADERS32 nt_headers32;
		IMAGE_NT_HEADERS64 nt_headers64;
	};
	// �ڱ�
	std::vector<IMAGE_SECTION_HEADER> section_headers;
}PEHeader;


class PEHelper {
private:
	// PE ����
	PEType type;
	// PE �ļ�ͷ
	PEHeader header;
	// PE ·��
	std::string path;

	void ReadMZHeader(const BYTE* buffer) {
		// �ж� MZ �ļ�ͷ
		if (!(buffer[0] == 0x4D && buffer[1] == 0x5A)) {
			std::cerr << "����MZ�ļ�ͷ" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		std::memcpy(&header.mz_header, buffer, sizeof(IMAGE_DOS_HEADER));
	}

	void GetPEType(const BYTE* buffer) {
		if (buffer[0] == 0x0B) {
			if (buffer[1] == 0x01) {
				type = PE32;
			}
			else if (buffer[1] == 0x02) {
				type = PE64;
			}
			else {
				std::cerr << "PE���ʹ���" << std::endl;
				std::exit(EXIT_FAILURE);
			}
		}
		else {
			std::cerr << "PE���ʹ���" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}

	void ReadNTHeaders(const BYTE* buffer) {
		// �ж� PE �ļ�ͷ
		if (!(buffer[0] == 0x50 && buffer[1] == 0x45)) {
			std::cerr << "����PE�ļ�" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		// PE ����λ��
		GetPEType(buffer + 24);
		
		switch (type) {
		case PE32: {
			std::memcpy(&header.nt_headers32, buffer, sizeof(IMAGE_NT_HEADERS32));
			break;
		}
		case PE64: {
			std::memcpy(&header.nt_headers64, buffer, sizeof(IMAGE_NT_HEADERS64));
			break;
		}
		default: {
			std::cerr << "����PE�ļ�" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		}
	}
	void ReadSectionHeader(const BYTE* buffer) {
		header.section_headers.clear();
		for (int i = 0; i != GetSectionsNumber(); i++) {
			IMAGE_SECTION_HEADER section_header;
			std::memcpy(&section_header, buffer + i * 0x28, sizeof(IMAGE_SECTION_HEADER));
			header.section_headers.push_back(section_header);
		}
	}

	void CheckSequenceZero(const BYTE* buffer, int length) {
		if (!IsSequenceZero(buffer, length)) {
			std::cerr << "�������" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}

	bool IsSequenceZero(const BYTE* buffer, int length) {
		for (int i = 0; i != length; i++) {
			if (buffer[i] != 0x00) {
				return false;
			}
		}
		return true;
	}

	// ������ '0x00' ��β���ַ����������ƶ��ļ�ָ��
	std::string ReadNextString(std::ifstream &file) {
		std::string name;
		while (true) {
			char c = file.get();
			if (c == 0x00) {
				return name;
			}
			name.push_back(c);
		}
	}

	// ��ȡ�ļ�����һ��˫��
	DWORD ReadNextDWORD(std::ifstream& file) {
		BYTE* buffer = new BYTE[sizeof(DWORD) + 1];
		for (int i = 0; i != sizeof(DWORD); i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		DWORD next;
		std::memcpy(&next, buffer, sizeof(DWORD));

		delete[] buffer;
		return next;
	}

	// ��ȡ�ļ�����һ����
	WORD ReadNextWORD(std::ifstream& file) {
		BYTE* buffer = new BYTE[sizeof(WORD) + 1];
		for (int i = 0; i != sizeof(WORD); i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		WORD next;
		std::memcpy(&next, buffer, sizeof(WORD));

		delete[] buffer;
		return next;
	}

	// д�ļ�����һ����
	void WriteNextWORD(std::ofstream& file, WORD word) {
		CHAR* buffer = new CHAR[sizeof(WORD) + 1];
		std::memcpy(buffer, &word, sizeof(WORD));

		if (!file.write(buffer, sizeof(WORD))) {
			std::cerr << "д���ļ�ʧ��" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		delete[] buffer;
	}

public:
	void ReadPEHeaderByName(std::string pe_path) {
		path = pe_path;

		std::ifstream file(pe_path, std::ios::binary);
		// �����ļ�ͷ������������
		BYTE* buffer = new BYTE[MAX_HEADER_LENGTH];
		// c++ Ϊɶ�������� char��
		int i = 0;
		while (file.good() && i < MAX_HEADER_LENGTH) {
			buffer[i] = file.get();
			i++;
		}
		ReadMZHeader(buffer);
		ReadNTHeaders(buffer + GetNTHeaderFOA());
		ReadSectionHeader(buffer + GetSectionHeaderFOA());

		file.close();
		delete[] buffer;
	}

	WORD GetSectionsNumber() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.FileHeader.NumberOfSections;
		}
		case PE64: {
			return header.nt_headers64.FileHeader.NumberOfSections;
		}
		}
	}

	DWORD GetNTHeaderFOA() {
		return header.mz_header.e_lfanew;
	}

	DWORD GetOptionalHeaderFOA() {
		return GetNTHeaderFOA() + 24;
	}

	DWORD GetSectionHeaderFOA() {
		return GetNTHeaderFOA() + IMAGE_SIZEOF_FILE_HEADER + GetSizeOfOptionalHeader() + 4;
	}

	WORD GetSizeOfOptionalHeader() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.FileHeader.SizeOfOptionalHeader;
		}
		case PE64: {
			return header.nt_headers64.FileHeader.SizeOfOptionalHeader;
		}
		}
	}

	DWORD GetSizeOfCode() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.SizeOfCode;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.SizeOfCode;
		}
		}
	}

	DWORD GetSizeOfHeaders() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.SizeOfHeaders;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.SizeOfHeaders;
		}
		}
	}

	DWORD GetEntryPointRVA() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.AddressOfEntryPoint;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.AddressOfEntryPoint;
		}
		}
	}

	DWORD GetEntryPointFOA() {
		return RVAToFOA(GetEntryPointRVA());
	}

	DWORD GetBaseOfCodeRVA() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.BaseOfCode;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.BaseOfCode;
		}
		}
	}

	ULONGLONG GetImageBase() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.ImageBase;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.ImageBase;
		}
		}
	}

	DWORD GetSectionAlignment() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.SectionAlignment;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.SectionAlignment;
		}
		}
	}

	DWORD GetFileAlignment() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.FileAlignment;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.FileAlignment;
		}
		}
	}

	DWORD RVAToFOA(DWORD rva) {
		// TODO
		// ����ٶ� rva С��һ���ļ�����ʱ��Ȼλ��ͷ��
		if (rva < GetSectionAlignment()) {
			return rva;
		}
		// ����ÿһ����
		for (auto it = header.section_headers.begin() + 1; it != header.section_headers.end(); it++) {
			if (rva < it->VirtualAddress) {
				it--;
				// ���� FOA ֮��Ĳ�ֵ���� RVA ֮��Ĳ�ֵ
				return it->PointerToRawData + rva - it->VirtualAddress;
			}
		}
		std::cerr << "RVA��������" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	// TODO
	// �����е���֣�VirtualAddress �ƺ����ᳬ�� DWORD
	// �Ȳ����� rva �� ULONGLONG �������
	//ULONGLONG RVAToFOA(ULONGLONG rva) {
	//	// TODO
	//	// ����ٶ� rva С��һ���ļ�����ʱ��Ȼλ��ͷ��
	//	if (rva < GetSectionAlignment()) {
	//		return rva;
	//	}
	//	// ����ÿһ����
	//	for (auto it = header.section_headers.begin() + 1; it != header.section_headers.end(); it++) {
	//		if (rva < it->VirtualAddress) {
	//			it--;
	//			// ���� FOA ֮��Ĳ�ֵ���� RVA ֮��Ĳ�ֵ
	//			return it->PointerToRawData + rva - it->VirtualAddress;
	//		}
	//	}
	//	std::cerr << "RVA��������" << std::endl;
	//	std::exit(EXIT_FAILURE);
	//}

	std::vector<std::string> GetSectionNames() {
		std::vector<std::string> names;
		for (auto it = header.section_headers.begin(); it != header.section_headers.end(); it++) {
			std::string name(8, 0);
			for (int i = 0; i != 8; i++) {
				name[i] = static_cast<char>(it->Name[i]);
			}
			names.push_back(name);
		}

		return names;
	}

	// TODO
	// 64 λ�ĵ������ 32 λ���Ƿ�һ��?
	// ͨ�����������ҵ�����ַ
	DWORD GetExportFunctionRVA(std::string name) {
		IMAGE_EXPORT_DIRECTORY export_directory = GetExportDirectory();
		DWORD names_foa = RVAToFOA(export_directory.AddressOfNames);
		DWORD ordinals_foa = RVAToFOA(export_directory.AddressOfNameOrdinals);
		DWORD address_foa = RVAToFOA(export_directory.AddressOfFunctions);

		std::ifstream file(path, std::ios::binary);
		// AddressOfNames �е�����
		DWORD index = 0;
		for (index; index != export_directory.NumberOfNames; index++) {
			file.seekg(names_foa + index * sizeof(DWORD), std::ios::beg);
			// ָ������
			DWORD name_foa = RVAToFOA(ReadNextDWORD(file));
			file.seekg(name_foa, std::ios::beg);
			std::string function_name = ReadNextString(file);
			if (function_name == name) {
				break;
			}
		}
		if (index == export_directory.NumberOfNames) {
			std::cerr << "�Ҳ�����Ӧ�ĵ�������" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		// �ҵ� AddressOfNameOrdianls �и�������Ӧ�����
		file.seekg(ordinals_foa + sizeof(WORD) * index, std::ios::beg);
		WORD ordinal_index = ReadNextWORD(file);
		
		// �� AddressOfFunctions ���ҵ���Ӧ�� RVA
		file.seekg(address_foa + sizeof(DWORD) * ordinal_index, std::ios::beg);
		DWORD function_rva = ReadNextDWORD(file);

		file.close();
		return function_rva;
	}

	std::vector<IMAGE_IMPORT_DESCRIPTOR> GetImageImportDescriptors() {
		IMAGE_DATA_DIRECTORY import_entry = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_IMPORT);
		DWORD import_entry_rva = import_entry.VirtualAddress;
		DWORD import_entry_size = import_entry.Size;
		DWORD import_descriptor_num = import_entry_size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;
		DWORD import_entry_foa = RVAToFOA(import_entry_rva);

		std::ifstream file(path, std::ios::binary);
		file.seekg(import_entry_foa, std::ios::beg);
		// �� image_import_descriptor ���뻺������
		BYTE* buffer = new BYTE[import_entry_size+1];
		for (DWORD i = 0; i <= import_entry_size; i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		file.close();

		std::vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor_vector;
		for (int i = 0; i != import_descriptor_num; i++) {
			IMAGE_IMPORT_DESCRIPTOR import_descriptor;
			std::memcpy(&import_descriptor, buffer + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
			import_descriptor_vector.push_back(import_descriptor);
		}
		// ����Ƿ��� 0 ����
		CheckSequenceZero(buffer + import_descriptor_num * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
		delete[] buffer;
		return import_descriptor_vector;
	}

	// �������е���� dll ����
	std::vector<std::string> GetImportDLLNames() {
		std::vector<std::string> names;

		std::ifstream file(path, std::ios::binary);
		std::vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor_vector = GetImageImportDescriptors();
		for (auto it = import_descriptor_vector.begin(); it != import_descriptor_vector.end(); it++) {
			DWORD name_rva = it->Name;
			DWORD name_foa = RVAToFOA(name_rva);
			file.seekg(name_foa, std::ios::beg);
			names.push_back(ReadNextString(file));
		}

		file.close();
		return names;
	}

	// ����Ŀ¼
	IMAGE_EXPORT_DIRECTORY GetExportDirectory() {
		IMAGE_DATA_DIRECTORY export_entry = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);
		DWORD export_rva = export_entry.VirtualAddress;
		if (export_rva == 0 || export_entry.Size == 0) {
			std::cerr << "û�е���Ŀ¼��" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		DWORD export_foa = RVAToFOA(export_rva);
		std::ifstream file(path, std::ios::binary);
		file.seekg(export_foa, std::ios::beg);

		IMAGE_EXPORT_DIRECTORY export_directory;
		BYTE* buffer = new BYTE[sizeof(IMAGE_EXPORT_DIRECTORY) + 1];
		for (int i = 0; i != sizeof(IMAGE_EXPORT_DIRECTORY); i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		std::memcpy(&export_directory, buffer, sizeof(IMAGE_EXPORT_DIRECTORY));

		file.close();
		delete[] buffer;
		return export_directory;
	}

	// TODO
	// ����дʵ����̫���ˣ��Ժ�һ��Ҫ���Է���
	// ���غ�����źͶ�Ӧ�ĺ�����
	std::vector<std::tuple<WORD, std::string>> GetImportFunctionNames(IMAGE_IMPORT_DESCRIPTOR descriptor) {
		std::vector<std::tuple<WORD, std::string>> result;

		std::ifstream file(path, std::ios::binary);
		// �洢��ŵ� buffer
		BYTE* buffer = new BYTE[sizeof(WORD) + 1];

		switch (type) {
		case PE32: {
			std::vector<IMAGE_THUNK_DATA32> thunk_data32 = GetImageThunkData32(descriptor);
			for (auto it = thunk_data32.begin(); it != thunk_data32.end(); it++) {
				// ������λ�� 1����ʾ��������͵���
				if (it->u1.Ordinal & 0x10000000) {
					std::cout << "��������͵��룬��֧�ֻ�ȡ������" << std::endl;
				}
				// ������һ��ָ�� IMAGE_IMPORT_BY_NAME �� rva
				else {
					DWORD foa = RVAToFOA(it->u1.AddressOfData);
					file.seekg(foa, std::ios::beg);

					for (int i = 0; i != sizeof(WORD); i++) {
						buffer[i] = static_cast<BYTE>(file.get());
					}
					// �������
					WORD hint;
					std::memcpy(&hint, buffer, sizeof(WORD));
					std::string name = ReadNextString(file);
					result.push_back(std::make_tuple(hint, name));
				}
			}
			break;
		}
		// ����һ��̫����
		case PE64: {
			std::vector<IMAGE_THUNK_DATA64> thunk_data64 = GetImageThunkData64(descriptor);
			for (auto it = thunk_data64.begin(); it != thunk_data64.end(); it++) {
				// ������λ�� 1����ʾ��������͵���
				if (it->u1.Ordinal & 0x10000000) {
					std::cout << "��������͵��룬��֧�ֻ�ȡ������" << std::endl;
				}
				// ������һ��ָ�� IMAGE_IMPORT_BY_NAME �� rva
				else {
					DWORD foa = RVAToFOA(it->u1.AddressOfData);
					file.seekg(foa, std::ios::beg);
					for (int i = 0; i != sizeof(WORD) + 1; i++) {
						buffer[i] = static_cast<BYTE>(file.get());
					}
					// �������
					WORD hint;
					std::memcpy(&hint, buffer, sizeof(WORD));
					std::string name = ReadNextString(file);
					result.push_back(std::make_tuple(hint, name));
				}
			}
			break;
		}
		}
		delete[] buffer;
		file.close();
		return result;
	}

	// TODO
	// �������ļ��� IAT �� INT �������һ�����������ֻ�� IAT �ж�
	std::vector<IMAGE_THUNK_DATA64> GetImageThunkData64(IMAGE_IMPORT_DESCRIPTOR descriptor) {
		std::vector<IMAGE_THUNK_DATA64> thunk_vector;
		DWORD thunk_rva = descriptor.FirstThunk;
		DWORD thunk_foa = RVAToFOA(thunk_rva);

		std::ifstream file(path, std::ios::binary);
		file.seekg(thunk_foa, std::ios::beg);
		// �洢 thunk �Ļ�����
		BYTE* buffer = new BYTE[sizeof(IMAGE_THUNK_DATA64) + 1];
		IMAGE_THUNK_DATA64 thunk;
		while (true) {
			for (int i = 0; i < sizeof(IMAGE_THUNK_DATA64); i++) {
				buffer[i] = static_cast<BYTE>(file.get());
			}
			if (IsSequenceZero(buffer, sizeof(IMAGE_THUNK_DATA64))) {
				return thunk_vector;
			}
			std::memcpy(&thunk, buffer, sizeof(IMAGE_THUNK_DATA64));
			thunk_vector.push_back(thunk);
		}
	}

	std::vector<IMAGE_THUNK_DATA32> GetImageThunkData32(IMAGE_IMPORT_DESCRIPTOR descriptor) {
		std::vector<IMAGE_THUNK_DATA32> thunk_vector;
		DWORD thunk_rva = descriptor.FirstThunk;
		DWORD thunk_foa = RVAToFOA(thunk_rva);

		std::ifstream file(path, std::ios::binary);
		file.seekg(thunk_foa, std::ios::beg);
		// �洢 thunk �Ļ�����
		BYTE* buffer = new BYTE[sizeof(IMAGE_THUNK_DATA32) + 1];
		IMAGE_THUNK_DATA32 thunk;
		while (true) {
			for (int i = 0; i < sizeof(IMAGE_THUNK_DATA32); i++) {
				buffer[i] = static_cast<BYTE>(file.get());
			}
			if (IsSequenceZero(buffer, sizeof(IMAGE_THUNK_DATA32))) {
				return thunk_vector;
			}
			std::memcpy(&thunk, buffer, sizeof(IMAGE_THUNK_DATA32));
			thunk_vector.push_back(thunk);
		}
	}

	IMAGE_DATA_DIRECTORY GetImageDataDirectorEntry(UINT32 index) {
		if (index < 0 || index > 15) {
			std::cerr << "����������Χ" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.DataDirectory[index];
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.DataDirectory[index];
		}
		}
	}

	// ASLR λ�ڿ�ѡ�ļ�ͷ�� DLL Characteristics
	// https://www.jianshu.com/p/91b2b6665e64
	bool HasASLR() {
		switch (type) {
		case PE32: {
			if (header.nt_headers32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
				return true;
			}
			return false;
		}
		case PE64: {
			if (header.nt_headers64.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
				return true;
			}
			return false;
		}
		}
	}
	
	// DLLCharacteristics �� 64 λ�� 32 λ PE �ļ����� Optional header ��ƫ������ͬ�ģ����� 70
	void ASLRAction(bool if_close) {
		// ע������� fstream ��Ҫָ���򿪵�����
		std::ifstream file_in(path, std::ios::binary);
		WORD dll_characteristics;

		// ��λ�� DllCharacteristics
		DWORD dll_characteristics_foa = GetOptionalHeaderFOA() + 70;
		file_in.seekg(dll_characteristics_foa, std::ios::beg);
		dll_characteristics = ReadNextWORD(file_in);
		file_in.close();
		if (if_close) dll_characteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		else dll_characteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		// ̫�ӵ��˰ɣ�Cܳ�������
		// ע���ȹرն�ȡ�ļ�������ʹ��׷��ģʽ��
		std::ofstream file_out(path, std::ios::binary || std::ios::app);
		file_out.seekp(dll_characteristics_foa, std::ios::beg);
		WriteNextWORD(file_out, dll_characteristics);
		file_out.close();

		// ���µ���
		ReadPEHeaderByName(path);
	}
	void CloseASLR() {
		ASLRAction(true);
	}

	void OpenASLR() {
		ASLRAction(false);
	}

	void DisplayPEInfo() {
		std::cout << "========================================================================\n\n";
		std::cout << "PE�ļ�·��: " << path << "\n";
		std::cout << "������ڵ�RVA: " << GetEntryPointRVA() << ", FOA: " << GetEntryPointFOA() << "\n";
		std::cout << "�ļ�����: " << GetFileAlignment() << "\n";
		std::cout << "�ڴ����: " << GetSectionAlignment() << "\n";
		std::cout << "������: " << GetSectionsNumber() << "\n";
		std::cout << "����Ϣ: \n";
		for (auto it = header.section_headers.begin(); it != header.section_headers.end(); it++) {
			std::cout << "--------------------------\n";
			std::cout << "����: " << it->Name << "\n";
			std::cout << "�ڴ�С: " << it->SizeOfRawData << "\n";
			std::cout << "����ʼRVA: " << it->VirtualAddress << "\n";
			std::cout << "����ʼFOA: " << it->PointerToRawData << "\n";
			std::cout << "--------------------------\n";
		}
		std::cout << "========================================================================\n" << std::endl;
	}
};
