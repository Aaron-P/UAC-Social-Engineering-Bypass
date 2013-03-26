#include <Windows.h>

//How can we pass the path to the payload?
//Via command line?
//Via edited resource?
//Via config file?
//Do multiple fallbacks?
//1) Passed path?
//2) _<dllname>.exe?
//3) _payload.exe?
//Same for config file if used?



//Create a specific export function, if you know what will be called when the dll is imported.
//extern "C" int __declspec(dllexport) example(HWND hwnd, HINSTANCE hinst, LPWSTR pszCmdLine, int nCmdShow)
//{
//
//	return 0;
//}


//
//   FUNCTION: IsUserInAdminGroup()
//
//   PURPOSE: The function checks whether the primary access token of the
//   process belongs to user account that is a member of the local
//   Administrators group, even if it currently is not elevated.
//
//   RETURN VALUE: Returns TRUE if the primary access token of the process
//   belongs to user account that is a member of the local Administrators
//   group. Returns FALSE if the token does not.
//
//   EXCEPTION: If this function fails, it throws a C++ DWORD exception which
//   contains the Win32 error code of the failure.
//
//   EXAMPLE CALL:
//     try
//     {
//         if (IsUserInAdminGroup())
//             wprintf (L"User is a member of the Administrators group\n");
//         else
//             wprintf (L"User is not a member of the Administrators group\n");
//     }
//     catch (DWORD dwError)
//     {
//         wprintf(L"IsUserInAdminGroup failed w/err %lu\n", dwError);
//     }
//
BOOL IsUserInAdminGroup()
{
	BOOL   fInAdminGroup = FALSE;
	DWORD  dwError       = ERROR_SUCCESS;
	HANDLE hToken        = NULL;
	HANDLE hTokenToCheck = NULL;
	DWORD  cbSize        = 0;
	OSVERSIONINFO osver  = {sizeof(osver)};

	// Open the primary access token of the process for query and duplicate.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether system is running Windows Vista or later operating
	// systems (major version >= 6) because they support linked tokens, but
	// previous versions (major version < 6) do not.
	if (!GetVersionEx(&osver))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	if (osver.dwMajorVersion >= 6)
	{
		// Running Windows Vista or later (major version >= 6).
		// Determine token type: limited, elevated, or default.
		TOKEN_ELEVATION_TYPE elevType;
		if (!GetTokenInformation(hToken, TokenElevationType, &elevType, sizeof(elevType), &cbSize))
		{
			dwError = GetLastError();
			goto Cleanup;
		}

		// If limited, get the linked elevated token for further check.
		if (TokenElevationTypeLimited == elevType)
		{
			if (!GetTokenInformation(hToken, TokenLinkedToken, &hTokenToCheck, sizeof(hTokenToCheck), &cbSize))
			{
				dwError = GetLastError();
				goto Cleanup;
			}
		}
	}

	// CheckTokenMembership requires an impersonation token. If we just got a
	// linked token, it already is an impersonation token.  If we did not get
	// a linked token, duplicate the original into an impersonation token for
	// CheckTokenMembership.
	if (!hTokenToCheck)
	{
		if (!DuplicateToken(hToken, SecurityIdentification, &hTokenToCheck))
		{
			dwError = GetLastError();
			goto Cleanup;
		}
	}

	// Create the SID corresponding to the Administrators group.
	BYTE adminSID[SECURITY_MAX_SID_SIZE];
	cbSize = sizeof(adminSID);
	if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &cbSize))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Check if the token to be checked contains admin SID.
	// http://msdn.microsoft.com/en-us/library/aa379596(VS.85).aspx:
	// To determine whether a SID is enabled in a token, that is, whether it
	// has the SE_GROUP_ENABLED attribute, call CheckTokenMembership.
	if (!CheckTokenMembership(hTokenToCheck, &adminSID, &fInAdminGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (hTokenToCheck)
	{
		CloseHandle(hTokenToCheck);
		hTokenToCheck = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fInAdminGroup;
}


//
//   FUNCTION: IsRunAsAdmin()
//
//   PURPOSE: The function checks whether the current process is run as
//   administrator. In other words, it dictates whether the primary access
//   token of the process belongs to user account that is a member of the
//   local Administrators group and it is elevated.
//
//   RETURN VALUE: Returns TRUE if the primary access token of the process
//   belongs to user account that is a member of the local Administrators
//   group and it is elevated. Returns FALSE if the token does not.
//
//   EXCEPTION: If this function fails, it throws a C++ DWORD exception which
//   contains the Win32 error code of the failure.
//
//   EXAMPLE CALL:
//     try
//     {
//         if (IsRunAsAdmin())
//             wprintf (L"Process is run as administrator\n");
//         else
//             wprintf (L"Process is not run as administrator\n");
//     }
//     catch (DWORD dwError)
//     {
//         wprintf(L"IsRunAsAdmin failed w/err %lu\n", dwError);
//     }
//
BOOL IsRunAsAdmin()
{
	BOOL  fIsRunAsAdmin        = FALSE;
	DWORD dwError              = ERROR_SUCCESS;
	PSID  pAdministratorsGroup = NULL;

	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsRunAsAdmin;
}


//
//   FUNCTION: IsProcessElevated()
//
//   PURPOSE: The function gets the elevation information of the current
//   process. It dictates whether the process is elevated or not. Token
//   elevation is only available on Windows Vista and newer operating
//   systems, thus IsProcessElevated throws a C++ exception if it is called
//   on systems prior to Windows Vista. It is not appropriate to use this
//   function to determine whether a process is run as administartor.
//
//   RETURN VALUE: Returns TRUE if the process is elevated. Returns FALSE if
//   it is not.
//
//   EXCEPTION: If this function fails, it throws a C++ DWORD exception
//   which contains the Win32 error code of the failure. For example, if
//   IsProcessElevated is called on systems prior to Windows Vista, the error
//   code will be ERROR_INVALID_PARAMETER.
//
//   NOTE: TOKEN_INFORMATION_CLASS provides TokenElevationType to check the
//   elevation type (TokenElevationTypeDefault / TokenElevationTypeLimited /
//   TokenElevationTypeFull) of the process. It is different from
//   TokenElevation in that, when UAC is turned off, elevation type always
//   returns TokenElevationTypeDefault even though the process is elevated
//   (Integrity Level == High). In other words, it is not safe to say if the
//   process is elevated based on elevation type. Instead, we should use
//   TokenElevation.
//
//   EXAMPLE CALL:
//     try
//     {
//         if (IsProcessElevated())
//             wprintf (L"Process is elevated\n");
//         else
//             wprintf (L"Process is not elevated\n");
//     }
//     catch (DWORD dwError)
//     {
//         wprintf(L"IsProcessElevated failed w/err %lu\n", dwError);
//     }
//
BOOL IsProcessElevated()
{
	BOOL fIsElevated = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;

	// Open the primary access token of the process with TOKEN_QUERY.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Retrieve token elevation information.
	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
	{
		// When the process is run on operating systems prior to Windows
		// Vista, GetTokenInformation returns FALSE with the
		// ERROR_INVALID_PARAMETER error code because TokenElevation is
		// not supported on those operating systems.
		dwError = GetLastError();
		goto Cleanup;
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsElevated;
}


//
//   FUNCTION: GetProcessIntegrityLevel()
//
//   PURPOSE: The function gets the integrity level of the current process.
//   Integrity level is only available on Windows Vista and newer operating
//   systems, thus GetProcessIntegrityLevel throws a C++ exception if it is
//   called on systems prior to Windows Vista.
//
//   RETURN VALUE: Returns the integrity level of the current process. It is
//   usually one of these values:
//
//     SECURITY_MANDATORY_UNTRUSTED_RID (SID: S-1-16-0x0)
//     Means untrusted level. It is used by processes started by the
//     Anonymous group. Blocks most write access.
//
//     SECURITY_MANDATORY_LOW_RID (SID: S-1-16-0x1000)
//     Means low integrity level. It is used by Protected Mode Internet
//     Explorer. Blocks write acess to most objects (such as files and
//     registry keys) on the system.
//
//     SECURITY_MANDATORY_MEDIUM_RID (SID: S-1-16-0x2000)
//     Means medium integrity level. It is used by normal applications
//     being launched while UAC is enabled.
//
//     SECURITY_MANDATORY_HIGH_RID (SID: S-1-16-0x3000)
//     Means high integrity level. It is used by administrative applications
//     launched through elevation when UAC is enabled, or normal
//     applications if UAC is disabled and the user is an administrator.
//
//     SECURITY_MANDATORY_SYSTEM_RID (SID: S-1-16-0x4000)
//     Means system integrity level. It is used by services and other
//     system-level applications (such as Wininit, Winlogon, Smss, etc.)
//
//   EXCEPTION: If this function fails, it throws a C++ DWORD exception
//   which contains the Win32 error code of the failure. For example, if
//   GetProcessIntegrityLevel is called on systems prior to Windows Vista,
//   the error code will be ERROR_INVALID_PARAMETER.
//
//   EXAMPLE CALL:
//     try
//     {
//         DWORD dwIntegrityLevel = GetProcessIntegrityLevel();
//     }
//     catch (DWORD dwError)
//     {
//         wprintf(L"GetProcessIntegrityLevel failed w/err %lu\n", dwError);
//     }
//
DWORD GetProcessIntegrityLevel()
{
	DWORD dwIntegrityLevel = 0;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	DWORD cbTokenIL = 0;
	PTOKEN_MANDATORY_LABEL pTokenIL = NULL;

	// Open the primary access token of the process with TOKEN_QUERY.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Query the size of the token integrity level information. Note that
	// we expect a FALSE result and the last error ERROR_INSUFFICIENT_BUFFER
	// from GetTokenInformation because we have given it a NULL buffer. On
	// exit cbTokenIL will tell the size of the integrity level information.
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL))
	{
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
		{
			// When the process is run on operating systems prior to Windows
			// Vista, GetTokenInformation returns FALSE with the
			// ERROR_INVALID_PARAMETER error code because TokenElevation
			// is not supported on those operating systems.
			dwError = GetLastError();
			goto Cleanup;
		}
	}

	// Now we allocate a buffer for the integrity level information.
	pTokenIL = (TOKEN_MANDATORY_LABEL *)LocalAlloc(LPTR, cbTokenIL);
	if (pTokenIL == NULL)
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Retrieve token integrity level information.
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Integrity Level SIDs are in the form of S-1-16-0xXXXX. (e.g.
	// S-1-16-0x1000 stands for low integrity level SID). There is one and
	// only one subauthority.
	dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (pTokenIL)
	{
		LocalFree(pTokenIL);
		pTokenIL = NULL;
		cbTokenIL = 0;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return dwIntegrityLevel;
}






void payloadW()
{







}










HMODULE GetCurrentModuleHandleW()
{
	HMODULE hMod = NULL;
	// Makes hMod NULL if it fails.
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)GetCurrentModuleHandleW, &hMod);
	return hMod;
}

bool getPathW(wchar_t *pathBuffer, const size_t bufferLength)
{
	if (bufferLength <= 0)
		return false;//Buffer is too small for anything.
	pathBuffer[0] = L'\0';

	HMODULE hMod = GetCurrentModuleHandleW();
	if (hMod != NULL)
	{
		GetModuleFileNameW(hMod, pathBuffer, bufferLength);//Error check this. Going from size_t to DWORD, might be an issue compiled as 64 bit (but probably not).
		return true;
	}
	return false;
}

bool getDirectoryW(wchar_t *directoryBuffer, const size_t bufferLength)
{
	if (bufferLength <= 0)
		return false;// Buffer is too small for anything.
	directoryBuffer[0] = L'\0';

	wchar_t pathBuffer[MAX_PATH];
	if (!getPathW(pathBuffer, sizeof(pathBuffer)/sizeof(wchar_t)))
		return false;// Could not get file path.

	const wchar_t *pathLastSlash = wcsrchr(pathBuffer, L'\\');

	if (pathLastSlash == NULL)
		return false;// Could not find a slash in the file path.

	const size_t directoryLength = pathLastSlash - pathBuffer + 1;

	if (directoryLength > bufferLength - 1)//Is this right, or should directoryLength be /sizeof(wchar_t)?
		return false;// Directory path is too long.

	if (wcsncpy_s(directoryBuffer, bufferLength, pathBuffer, directoryLength))// is it good practice to append a null anway?
		return false;// Some error occured while copying the directory path.
	return true;
}

int runasW(const wchar_t *lpFile, const wchar_t *lpParameters, const int nShowCmd)
{
	ShellExecuteW(NULL, L"runas", lpFile, lpParameters, NULL, nShowCmd);//SW_HIDE
	return 0;
}





BOOL WINAPI InitOnceExecuteOnce(PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, LPVOID *Context)
{
	ShellExecuteA(NULL, "runas", "C:\\WINDOWS\\system32\\cmd.exe", NULL, NULL, SW_SHOWDEFAULT);//SW_HIDE
	exit(0);
}

bool derp()
{
	ShellExecuteA(NULL, "runas", "C:\\WINDOWS\\system32\\cmd.exe", NULL, NULL, SW_SHOWDEFAULT);//SW_HIDE
	exit(1);
	return false;
}

// Useing DllMain to execute our payload is wonky (it really isn't meant to do this).
// If any calls block execution the process will hang.

//hinstDLL same as GetModuleHandleExW return value for dll, the entry point
bool WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
//	ShellExecuteW(NULL, L"open", L"C:\\WINDOWS\\system32\\cmd.exe", NULL, NULL, SW_SHOWDEFAULT);//SW_HIDE
//	exit(0);
//	return true;

	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			// Initialize once for each new process.
			// Return FALSE to fail DLL load.

			if (IsUserInAdminGroup())
			{
				if (IsProcessElevated())
				{
					//Execute the payload exe.
//					payloadW();
				}
				else
				{
					//Execute runas exe?

					//CANNOT DO RUNAS IN DLLMAIN, WILL HANG PROCESS
//					ShellExecuteW(NULL, L"runas", L"cmd.exe", NULL, NULL, SW_SHOWDEFAULT);//SW_HIDE
				}
			}

			exit(0);

			if (IsUserInAdminGroup())
				MessageBoxW(NULL, L"User is admin", L"Test", MB_ICONEXCLAMATION | MB_OK);
			else
				MessageBoxW(NULL, L"User is not admin", L"Test", MB_ICONEXCLAMATION | MB_OK);

			if (IsRunAsAdmin())
				MessageBoxW(NULL, L"Process is admin", L"Test", MB_ICONEXCLAMATION | MB_OK);
			else
				MessageBoxW(NULL, L"Process is not admin", L"Test", MB_ICONEXCLAMATION | MB_OK);

			if (IsProcessElevated())
				MessageBoxW(NULL, L"Process is elevated", L"Test", MB_ICONEXCLAMATION | MB_OK);
			else
				MessageBoxW(NULL, L"Process is not elevated", L"Test", MB_ICONEXCLAMATION | MB_OK);






//			MessageBoxW(NULL, L"Test", L"Test", MB_ICONEXCLAMATION | MB_OK);
			exit(0);
			break;

		case DLL_THREAD_ATTACH:
			// Do thread-specific initialization.
			break;

		case DLL_THREAD_DETACH:
			// Do thread-specific cleanup.
			break;

		case DLL_PROCESS_DETACH:
			// Perform any necessary cleanup.
			break;
	}
	return true;
}
