#include "utils.hpp"


UINT16 ReadWORD(const BYTE* buffer) {
	// �ȶ���λ�ֽ�
	UINT16 result = (UINT8)buffer[1];
	result <<= 8;
	result += (UINT8)buffer[0];

	return result;
}


UINT32 ReadDWORD(const BYTE* buffer) {
	// �ȶ���λ�ֽ�
	UINT32 result = 0;
	for (int i = 0; i != 4; i++) {
		UINT32 tmp = buffer[i];
		tmp <<= (i * 8);
		result += tmp;
	}
	return result;
}
