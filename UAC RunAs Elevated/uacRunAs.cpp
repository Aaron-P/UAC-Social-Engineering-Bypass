#include <Windows.h>
#include <string>
using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	LPWSTR *szArglist;
	int nArgs;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist == NULL)
		return 1;//Parsing messed up.
   
	if (nArgs < 2)//Is the first arg always the exe?
		return 1;//No parameters passed.

	/*
	//Redo this using standard wchar in a better way
	wstring params = L"";
	if (nArgs > 2)
	{
		for (int i = 2; i < nArgs; i++)
		{
			if (i != 2)
				params += L" ";
			params += szArglist[i];
		}
	}

	//check first param that path is good and exists
	ShellExecuteW(NULL, L"runas", szArglist[1], params.c_str(), NULL, SW_HIDE);//SW_HIDE
	*/

	ShellExecuteW(NULL, L"runas", szArglist[1], NULL, NULL, SW_SHOW);//SW_HIDE
	LocalFree(szArglist);

	return 0;
}

