#include <Windows.h>
#include <string>
#include <fstream>

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )
#pragma warning(disable:4996)

bool struct_check(std::string pe_path, bool& is_32, std::string& ret_info)
{
	std::fstream pe_file;
	pe_file.open(pe_path, std::ios::in);
	if (!pe_file.is_open())
	{
		ret_info = "File open failed!\r\n";
		return false;
	}
	IMAGE_DOS_HEADER dos_header;
	pe_file.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		ret_info = "IMAGE_DOS_SIGNATURE MZ not find!\r\n";
		pe_file.close();
		return false;
	}
	IMAGE_NT_HEADERS nt_header;
	pe_file.seekp(dos_header.e_lfanew);
	pe_file.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS));
	if (nt_header.Signature != IMAGE_NT_SIGNATURE)
	{
		ret_info = "IMAGE_NT_SIGNATURE PE not find!\r\n";
		pe_file.close();
		return false;
	}
	if (nt_header.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		is_32 = true;
		pe_file.close();
		return true;
	}
	if (nt_header.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 || nt_header.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		is_32 = false;
		pe_file.close();
		return true;
	}
	else
	{
		ret_info = "not 32/64 PE,other case\r\n";
		pe_file.close();
		return false;
	}

	ret_info = "Unknown Error";
	return false;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		MessageBox(NULL, "SWBinBit.exe\r\n Usage:\r\n SWBinBit [EXE/DLL]\r\n", "Format Error", NULL);
		return -1;
	}

	bool is_32 = false;
	std::string ret_info = "Success";
	if (!struct_check(argv[1], is_32, ret_info)) {
		MessageBox(NULL, ("File: " + std::string(argv[1]) + "\r\nFailed, " + ret_info).c_str(), "SWBinBit", MB_ICONERROR);
		return -1;
	}

	switch (is_32)
	{
	case true:
		MessageBox(NULL, ("[32-bit]\r\nFile: " + std::string(argv[1])).c_str(), "SWBinBit", NULL);
		break;

	case false:
		MessageBox(NULL, ("[64-bit]\r\nFile: " + std::string(argv[1])).c_str(), "SWBinBit", NULL);
		break;
	}

	return 0;
}
