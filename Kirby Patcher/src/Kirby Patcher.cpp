#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

/*
Init()
Hex: E8 3D D5 01 00
RVA: 0x6618E
call --> nop

IsBlacklisted()
Hex: E8 94 9B 01 00
RVA: 0x66857
call --> nop

IsBlacklisted
Hex: 0F 84 F2 03 00 00
RVA: 0x6686E
je --> jmp

CheckVersion()
Hex: E8 A9 34 02 00
RVA: 0x66DA2
call --> nop

CheckVersion
Hex: 72 34
RVA: 0x66DF1
jb --> jmp

Check()
Hex: 0F 84 5C 0A 00 00
RVA: 0x66E46
je --> jmp

AutoLogin()
Hex: E8 85 C8 01 00
RVA: 0x684F6
call --> nop

AutoLogin
Hex: 0F 84 71 1E 00 00
RVA: 0x68502
je --> nop

Login()
Hex: E8 CA A5 01 00
RVA: 0x6A7B1
call --> nop

Login
Hex: 0F 84 99 1D 00 00
RVA: 0x6A7BD
je --> nop

AuthCheck()
Hex: E8 F0 F6 01 00
RVA: 0x6568B
call --> nop

FailureExit()
Hex: FF D0
RVA: 0x65745
call --> nop
*/

namespace proc {
	DWORD procId = NULL;
	HANDLE hProc = nullptr;

	DWORD GetProcId(const wchar_t* procName) {
		DWORD procId = NULL;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 procEntry;
			procEntry.dwSize = sizeof(procEntry);
			if (Process32First(hSnap, &procEntry)) {
				do {
					if (!_wcsicmp(procEntry.szExeFile, procName)) {
						procId = procEntry.th32ProcessID;
						break;
					}
				} while (Process32Next(hSnap, &procEntry));
			}
		}
		CloseHandle(hSnap);
		return procId;
	}

	uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
		uintptr_t modBaseAddr = NULL;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
		if (hSnap != INVALID_HANDLE_VALUE) {
			MODULEENTRY32 modEntry;
			modEntry.dwSize = sizeof(modEntry);
			if (Module32First(hSnap, &modEntry)) {
				do {
					if (!_wcsicmp(modEntry.szModule, modName)) {
						modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
						break;
					}
				} while (Module32Next(hSnap, &modEntry));
			}
		}
		CloseHandle(hSnap);
		return modBaseAddr;
	}

	void SuspendProcess(DWORD procId) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			THREADENTRY32 threadEntry;
			threadEntry.dwSize = sizeof(threadEntry);
			if (Thread32First(hSnap, &threadEntry)) {
				do {
					if (threadEntry.th32OwnerProcessID == procId) {
						HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
						if (hThread != INVALID_HANDLE_VALUE) {
							SuspendThread(hThread);
							CloseHandle(hThread);
						}
					}
				} while (Thread32Next(hSnap, &threadEntry));
			}
		}
		CloseHandle(hSnap);
	}
	
	void ResumeProcess(DWORD procId) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			THREADENTRY32 threadEntry;
			threadEntry.dwSize = sizeof(threadEntry);
			if (Thread32First(hSnap, &threadEntry)) {
				do {
					if (threadEntry.th32OwnerProcessID == procId) {
						HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
						if (hThread != INVALID_HANDLE_VALUE) {
							ResumeThread(hThread);
							CloseHandle(hThread);
						}
					}
				} while (Thread32Next(hSnap, &threadEntry));
			}
		}
		CloseHandle(hSnap);
	}
}

namespace mem {
	void PatchEx(BYTE* dst, BYTE* src, unsigned int size, HANDLE hProcess) {
		DWORD oldprotect;
		VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
		WriteProcessMemory(hProcess, dst, src, size, nullptr);
		VirtualProtectEx(hProcess, dst, size, oldprotect, &oldprotect);
	}

	BYTE* ReadEx(HANDLE hProcess, uintptr_t src, uintptr_t size) {
		BYTE* buffer = new BYTE[size];
		ReadProcessMemory(hProcess, (BYTE*)src, buffer, size, nullptr);
		return buffer;
	}

	void NopEx(BYTE* dst, unsigned int size, HANDLE hProcess) {
		BYTE* nopArray = new BYTE[size];
		memset(nopArray, 0x90, size);

		PatchEx(dst, nopArray, size, hProcess);
		delete[] nopArray;
	}
}

namespace offsets {
	uintptr_t InitFuncCall = 0x6618E;
	uintptr_t IsBlacklistedFuncCall = 0x66857;
	uintptr_t IsBlacklistedRetCheck = 0x6686E;
	uintptr_t CheckVersionFuncCall = 0x66DA2;
	uintptr_t CheckVersionRetCheck = 0x66DF1;
	uintptr_t CheckRetCheck = 0x66E46;
	uintptr_t AutoLoginFuncCall = 0x684F6;
	uintptr_t AutoLoginRetCheck = 0x68502;
	uintptr_t LoginFuncCall = 0x6A7B1;
	uintptr_t LoginRetCheck = 0x6A7BD;
	uintptr_t AuthCheckFuncCall = 0x6568B;
	uintptr_t FailureExitFuncCall = 0x65745;
}

int main() {
	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r);
	MoveWindow(console, r.left, r.top, 700, 450, TRUE);
	SetWindowLong(console, GWL_STYLE, GetWindowLong(console, GWL_STYLE) & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX);
	SetWindowPos(console, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	SetConsoleTitle(L"Kirby Patcher");
	
	int delay = 400;
	uintptr_t procId = 0;
	HANDLE hProcess = 0;
	uintptr_t moduleBase = 0;

	FILE* fp;
	errno_t err = fopen_s(&fp, "PatcherDelay_ms.cfg", "r");
	if (err == 0) {
		fscanf_s(fp, "%d", &delay);
		fclose(fp);
	}
	else {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "PatcherDelay_ms.cfg not found, using default delay of 400ms\n\n";
	}

	if (GetFileAttributes(L"kirby.exe") == INVALID_FILE_ATTRIBUTES) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		std::cout << "kirby.exe not found. Please place it in the same folder\n";
		getchar();
		return 0;
	}
	
	ShellExecute(0, 0, L"kirby.exe", 0, 0, SW_SHOW);

	procId = proc::GetProcId(L"kirby.exe");
	if (!procId) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		std::cout << "Process not found, press enter to exit\n";
		getchar();
		return 0;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, procId);
	
	moduleBase = proc::GetModuleBaseAddress(procId, L"kirby.exe");
	if (!moduleBase) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		std::cout << "Module not found, press enter to exit\n";
		getchar();
		return 0;
	}

	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		std::cout << "ProcID:     ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << procId << std::endl;

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		std::cout << "ModuleBase: ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "0x" << std::hex << moduleBase << std::endl << std::endl;
	}

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	std::cout << "Please wait while the target program is being unpacked...\n";
	while (true) {
		BYTE* originalBytes = (BYTE*)"\xE8\x3D\xD5\x01\x00";
		BYTE* initFuncCall = mem::ReadEx(hProcess, moduleBase + offsets::InitFuncCall, 5);
		if (!memcmp(originalBytes, initFuncCall, 5)) {
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
			std::cout << "Process unpacked successfully\n\n";
			break;
		}
	}
	
	Sleep(delay);
	
	proc::SuspendProcess(procId);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	std::cout << "[Process suspended]\n";
	{
		mem::NopEx((BYTE*)(moduleBase + offsets::InitFuncCall), 5, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[1/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::IsBlacklistedFuncCall), 5, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[2/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::PatchEx((BYTE*)(moduleBase + offsets::IsBlacklistedRetCheck), (BYTE*)"\xE9\xF3\x03\x00\x00\x90", 6, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[3/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::CheckVersionFuncCall), 5, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[4/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::PatchEx((BYTE*)(moduleBase + offsets::CheckVersionRetCheck), (BYTE*)"\xEB\x34", 2, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[5/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::PatchEx((BYTE*)(moduleBase + offsets::CheckRetCheck), (BYTE*)"\xE9\x5D\x0A\x00\x00\x90", 6, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[6/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::AutoLoginFuncCall), 5, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[7/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::AutoLoginRetCheck), 6, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[8/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::LoginFuncCall), 5, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[9/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::LoginRetCheck), 6, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[10/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::AuthCheckFuncCall), 5, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[11/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";

		mem::NopEx((BYTE*)(moduleBase + offsets::FailureExitFuncCall), 2, hProcess);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
		std::cout << "[12/12] ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		std::cout << "Patched\n";
	}
	proc::ResumeProcess(procId);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	std::cout << "[Process resumed]\n\n";
	
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
	std::cout << "All patches have been applied successfully\n";
	Sleep(5000);

	return 0;
}
