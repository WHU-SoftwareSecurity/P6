#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include <Windows.h>
#include "pe.hpp"
#include "virus.hpp"


using namespace std;


int main() {
	cout << hex;
	string pe_file("./hello_world.exe");
	PEHelper pe_info;
	pe_info.LoadPE(pe_file);
	pe_info.DisplayPEInfo();

	InfectHelper vh(pe_file);

	cout << vh.IsInfected();
	cout << vh.InfectByCodeCave();
	cout << vh.IsInfected();
	cout << vh.RemoveVirus();
	cout << vh.InfectByAddSection();
	cout << vh.RemoveVirus();
	cout << vh.IsInfected();
	return 0;
}