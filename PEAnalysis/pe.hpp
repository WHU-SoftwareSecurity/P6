#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <map>
#include <tuple>


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
			std::cerr << "��д���ļ�ʧ��" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		delete[] buffer;
	}

	// д�ļ�����һ��˫��
	void WriteNextDWORD(std::ofstream& file, DWORD dword) {
		CHAR* buffer = new CHAR[sizeof(DWORD) + 1];
		std::memcpy(buffer, &dword, sizeof(DWORD));

		if (!file.write(buffer, sizeof(DWORD))) {
			std::cerr << "˫��д���ļ�ʧ��" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		delete[] buffer;
	}

	// ���������� size ��С������д���ļ�
	void WriteBuffer(std::ofstream& file, const CHAR* buffer, ULONGLONG size) {
		if (!file.write(buffer, size)) {
			std::cerr << "������д���ļ�ʧ��" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}

	// ���ַ������㣬ʹ�䰴���ļ�����
	void ToFileAlignment(std::string& str) {
		DWORD append_num = str.size() % GetFileAlignment();
		if (append_num) {
			append_num = GetFileAlignment() - append_num;
		}
		for (DWORD i = 0; i != append_num; i++) {
			str.push_back(0x00);
		}
	}


	// �����ڴ�����Ĵ�С
	DWORD ToSectionAlignment(DWORD size) {
		// �����ڴ����
		DWORD section_alignment = GetSectionAlignment();
		if (size % section_alignment) {
			return (1 + (size / section_alignment)) * section_alignment;
		}
		return size;
	}

public:
	void LoadPE(std::string pe_path) {
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

	// ��ȡ������
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

	// NTӳ��ͷ FOA
	DWORD GetNTHeaderFOA() {
		return header.mz_header.e_lfanew;
	}

	// ���ؿ�ѡ�ļ�ͷ��ʼ FOA
	DWORD GetOptionalHeaderFOA() {
		return GetNTHeaderFOA() + 24;
	}

	// ���ؽڱ�ͷ��ʼ FOA
	DWORD GetSectionHeaderFOA() {
		return GetNTHeaderFOA() + IMAGE_SIZEOF_FILE_HEADER + GetSizeOfOptionalHeader() + 4;
	}

	// ���ؽڱ�ͷ��ĩβ FOA
	DWORD GetEndSectionHeaderFOA() {
		return IMAGE_SIZEOF_SECTION_HEADER * GetSectionsNumber() + GetSectionHeaderFOA();
	}

	// ���Ҫ�����ӽڣ���ý���ʼ�� FOA
	// TODO
	// �����и�����
	// ����ĳЩ�ļ�(user32.dll)���ڵ�ĩβ�����ļ���ĩβ
	// �ƺ��� certification table
	ULONGLONG GetNewSectionFOA() {
		// ȷ��û�� Certification table
		IMAGE_DATA_DIRECTORY certification_table = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_SECURITY);
		if (certification_table.Size || certification_table.VirtualAddress) {
			std::cerr << "��֧������ Certification Table ��PE�ļ���������" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		ULONGLONG file_size = GetFileSize();
		if (file_size % GetFileAlignment()) {
			std::cerr << "��ֵĴ����ļ���С�������ļ�����" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		return file_size;
	}

	// �½ڵ���ʼ RVA
	ULONGLONG GetNewSectionRVA() {
		// ȷ��û�� Certification table
		IMAGE_DATA_DIRECTORY certification_table = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_SECURITY);
		if (certification_table.Size || certification_table.VirtualAddress) {
			std::cerr << "��֧������ Certification Table ��PE�ļ���������" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		// ������ͷ�ҵ����һ����
		int last_header_index = 0;
		for (int i = 1; i < header.section_headers.size(); i++) {
			if (header.section_headers[i].VirtualAddress > header.section_headers[last_header_index].VirtualAddress) {
				last_header_index = i;
			}
		}
		DWORD last_header_rva = header.section_headers[last_header_index].VirtualAddress;
		DWORD last_header_size = header.section_headers[last_header_index].SizeOfRawData;
		// �����ڴ����
		return last_header_rva + ToSectionAlignment(last_header_size);
	}

	// �����ļ��Ĵ�С
	ULONGLONG GetFileSize() {
		return std::filesystem::file_size(path);
	}

	// ���ؿ�ѡ�ļ�ͷ�Ĵ�С
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

	// ���ش���εĴ�С
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

	// ����ͷ��(����MZͷ��DOS Stub��NTӳ��ͷ�ͽڱ�)�Ĵ�С
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

	// ������� RVA
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

	// ���ó�����ڵ�
	void SetEntryPoint(DWORD entry_point) {
		std::ofstream file(path, std::ios::binary || std::ios::ate);
		// 64 λ�� 32 λ��ƫ�����
		file.seekp(GetOptionalHeaderFOA() + 16, std::ios::beg);
		
		WriteNextDWORD(file, entry_point);

		file.close();
	}

	// ������ڵ��Ӧ FOA
	DWORD GetEntryPointFOA() {
		return RVAToFOA(GetEntryPointRVA());
	}
	
	// ����� RVA
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
	
	// �ڴ����
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

	// �ڶ���
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

	// ��ȡ���нڵ�����
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

	// ��ȡ���е� Import Descriptor
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

	// ���е� thunk data
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
		LoadPE(path);
	}
	void CloseASLR() {
		ASLRAction(true);
	}

	void OpenASLR() {
		ASLRAction(false);
	}

	IMAGE_SECTION_HEADER CreateNewSectionHeader(
		const BYTE* name,
		const DWORD characteristics = 0,
		const DWORD rva = 0,
		const DWORD foa = 0,
		const DWORD size = 0,
		const DWORD misc = 0,
		const DWORD pointer_to_relocations = 0,
		const WORD pointer_to_linenumbers = 0,
		const WORD number_of_relocations = 0,
		const WORD number_of_linenumbers = 0
	) {
		IMAGE_SECTION_HEADER header;
		std::memcpy(&header.Name, name, IMAGE_SIZEOF_SHORT_NAME);
		std::memcpy(&header.Misc, &misc, sizeof(DWORD));
		header.VirtualAddress = rva;
		header.SizeOfRawData = size;
		header.PointerToRawData = foa;
		header.PointerToRelocations = pointer_to_relocations;
		header.PointerToLinenumbers = pointer_to_linenumbers;
		header.NumberOfRelocations = number_of_relocations;
		header.NumberOfLinenumbers = number_of_linenumbers;
		header.Characteristics = characteristics;
		
		return header;
	}

	// ���һ���½�
	// �������²���
	//		1. ���ļ�ĩβ׷��дһ���½�(��Ҫע�ⲻ�����ļ�����Ĳ���Ҫ����)
	//		2. �ڽڱ�������һ����ͷ
	//		3. ���� FILE_HEADER �е� NumberOfSections �ֶ�
	//		4. ������ѡ�ļ�ͷ�е� SizeOfImage
	void AddNewSection(
		std::string buffer,
		const BYTE* name,
		// Ĭ��Ȩ��Ϊ��д��ִ�д���
		const DWORD characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
	) {
		std::ofstream file(path, std::ios::binary || std::ios::ate);
		
		// ����ʹ���ļ�����
		ToFileAlignment(buffer);
		
		// ��ʼ����ͷ
		// ��������Ĭ�ϲ���̫����
		IMAGE_SECTION_HEADER section_header = CreateNewSectionHeader(name, characteristics, GetNewSectionRVA(), GetNewSectionFOA(), buffer.size());
		
		// д���½ڵĲ�����Ҫ�ڴ�����ͷ֮��
		file.seekp(GetNewSectionFOA(), std::ios::beg);
		// ���ļ���ĩβд���½�
		WriteBuffer(file, buffer.c_str(), buffer.size());
		// ֱ��д���ļ������ڵ���
		//file.flush();

		// ��λ���ڱ�ͷ��ĩβ
		file.seekp(GetEndSectionHeaderFOA(), std::ios::beg);
		// ���ڱ�ͷ�����ݷŵ�������������
		CHAR* header_buffer = new CHAR[IMAGE_SIZEOF_SECTION_HEADER + 1];
		std::memcpy(header_buffer, &section_header, IMAGE_SIZEOF_SECTION_HEADER);
		// д��ڱ�ͷ
		WriteBuffer(file, header_buffer, IMAGE_SIZEOF_SECTION_HEADER);
		delete[] header_buffer;

		switch (type) {
		case PE32: {
			// ��λ�� NumberOfSections �ֶ�
			file.seekp(GetNTHeaderFOA() + 6, std::ios::beg);
			WORD new_section_number = header.nt_headers32.FileHeader.NumberOfSections + 1;
			WriteNextWORD(file, new_section_number);
			// �����½ں����ڴ��еĴ�С
			DWORD new_image_size = header.nt_headers32.OptionalHeader.SizeOfImage + ToSectionAlignment(section_header.SizeOfRawData);
			// ��λ�� SizeofImage �ֶ�
			file.seekp(GetOptionalHeaderFOA() + 56, std::ios::beg);
			WriteNextDWORD(file, new_image_size);
			break;
		}
		case PE64: {
			// ��λ�� NumberOfSections �ֶ�
			file.seekp(GetNTHeaderFOA() + 6, std::ios::beg);
			WORD new_section_number = header.nt_headers64.FileHeader.NumberOfSections + 1;
			WriteNextWORD(file, new_section_number);
			// �����½ں����ڴ��еĴ�С
			DWORD new_image_size = header.nt_headers64.OptionalHeader.SizeOfImage + ToSectionAlignment(section_header.SizeOfRawData);
			// ��λ�� SizeofImage �ֶ�
			file.seekp(GetOptionalHeaderFOA() + 56, std::ios::beg);
			WriteNextDWORD(file, new_image_size);
			break;
		}
		}

		file.close();
	}

	void DisplayPEInfo() {
		std::cout << "========================================================================\n\n";
		std::cout << "PE�ļ�·��: " << path << "\n";
		std::cout << "�ļ���С: " << GetFileSize() << "\n";
		std::cout << "ImageBase: " << GetImageBase() << "\n";
		std::cout << "������ڵ�RVA: " << GetEntryPointRVA() << ", FOA: " << GetEntryPointFOA() << "\n";
		std::cout << "�ļ�����: " << GetFileAlignment() << "\n";
		std::cout << "�ڴ����: " << GetSectionAlignment() << "\n";
		std::cout << "�ļ�ͷռ���̴�С: " << GetSizeOfHeaders() << "\n";
		std::cout << "�ļ�ͷʵ�ʴ�С(�ڱ�ͷĩβ): " << GetEndSectionHeaderFOA() << "\n\n";
		std::cout << "����Ϣ: \n";
		std::cout << "������: " << GetSectionsNumber() << "\n";
		std::cout << "�ڱ�ͷ��ʼFOA: " << GetSectionHeaderFOA() << "\n";
		std::cout << "�ڱ�ͷĩβFOA: " << GetEndSectionHeaderFOA() << "\n";
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
