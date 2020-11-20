#include "utils.hpp"
#include <iostream>
#include <fstream>

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
std::string ReadNextString(std::ifstream& file) {
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