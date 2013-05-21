#include <Windows.h>
#include <string>
using namespace std;

bool getFileNameW(wchar_t *fileNameBuffer, const size_t bufferLength)
{
	if (bufferLength <= 0)
		return false;// Buffer is too small for anything.
	fileNameBuffer[0] = L'\0';

	wchar_t pathBuffer[MAX_PATH];
	size_t pathSize = GetModuleFileNameW(NULL, pathBuffer, sizeof(pathBuffer)/sizeof(wchar_t));
	if (pathSize == 0)
		return false;// Could not get file path.

	const wchar_t *pathLastSlash = wcsrchr(pathBuffer, L'\\');

	if (pathLastSlash == NULL)
		return false;// Could not find a slash in the file path.

	const size_t fileNameLength = (pathBuffer + pathSize) - pathLastSlash;//Should this be +/- 1?

	if (fileNameLength > bufferLength - 1)//Is this right, or should fileNameLength be /sizeof(wchar_t)?
		return false;// File name is too long.

	if (wcsncpy_s(fileNameBuffer, bufferLength, pathLastSlash + 1, fileNameLength))// is it good practice to append a null anway?
		return false;// Some error occured while copying the file name.
	return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	LPWSTR *szArglist;
	int nArgs;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist == NULL)
		return 1;//Parsing messed up.

	if (nArgs < 1)
		return 1;//No arguments were passed at all (weird).

	wchar_t fileName[MAX_PATH];
	getFileNameW(fileName, sizeof(fileName)/sizeof(wchar_t));//Should this be MAX_PATH?
	bool skipFirstArg = (bool)(!wcsncmp(szArglist[0], fileName, MAX_PATH));//Check if first argument is the executable path (likely). Should this be sizeof(fileName)/sizeof(wchar_t)?

	if (skipFirstArg && nArgs < 2)
		return 1;//First argument is the executable path, no other arguments passed.



	//Redo this using standard wchar in a better way
	wstring params = L"";

	int i = 1;
	if (skipFirstArg)
		i = 2;

	bool first = true;
	for (; i < nArgs; i++)
	{
		if (first)
		{
			params += szArglist[i];
			first = false;
		}
		else
		{
			params += L" ";
			params += szArglist[i];
		}
	}




	//Check first param that path is good and exists.
	ShellExecuteW(NULL, L"runas", szArglist[1], params.c_str(), NULL, SW_HIDE);//SW_HIDE
	LocalFree(szArglist);

	return 0;
}

