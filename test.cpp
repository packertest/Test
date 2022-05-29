//////////////////////////////////////////////////////
//
//      windows https request
//
//////////////////////////////////////////////////////

#include<Windows.h>
#include<wininet.h>

#pragma comment (lib, "wininet.lib")

int main() 
{
	// establish a session
	HINTERNET hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0", 
		INTERNET_OPEN_TYPE_PRECONFIG, 
		NULL, NULL, 0);
	
	// establish connection
	HINTERNET hConnect = InternetConnectA(hInternet, "xxx.xxx.xxx.xxx",
		INTERNET_DEFAULT_HTTPS_PORT, 
		NULL, NULL, 
		INTERNET_SERVICE_HTTP, 
		NULL, NULL);
	

	DWORD dwOpenRequestFlags = INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP |
		INTERNET_FLAG_KEEP_CONNECTION |
		INTERNET_FLAG_NO_AUTH |
		INTERNET_FLAG_NO_COOKIES |
		INTERNET_FLAG_NO_UI |
		INTERNET_FLAG_RELOAD |
		// https setting
		INTERNET_FLAG_SECURE | // start https
		INTERNET_FLAG_IGNORE_CERT_CN_INVALID; // Ignore invalid https certificates
	
	// open request
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET",
		"/index.html", "HTTP/1.1",  NULL, NULL,  dwOpenRequestFlags, NULL);


	// send request
	DWORD dwFlags = dwFlags | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	HttpSendRequest(hRequest, NULL, 0, NULL, 0);


	char* pResponseHeaderInfo = new char[0x1000];
	if (pResponseHeaderInfo != NULL) {
		memset(pResponseHeaderInfo, 0, 0x1000);

		DWORD dwResponseHeaderInfoSize = 0;
		// recv server data
		HttpQueryInfoA(hRequest,  HTTP_QUERY_RAW_HEADERS_CRLF, pResponseHeaderInfo, &dwResponseHeaderInfoSize, NULL);

		DWORD dwRealWord;
		BOOL response = InternetReadFile(hRequest, lpBuffer, dwNumberOfBytesToRead, &dwRealWord);
	}

	// close handle
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);

	return 0;
}



//////////////////////////////////////////////////////
//
//      windows enum process
//
//////////////////////////////////////////////////////

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>

int main()
{
	HANDLE h_process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h_process_snap == INVALID_HANDLE_VALUE) {
		printf("[CreateToolhelp32Snapshot error id]: %d\r\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe32;	// save process infomation struct
	pe32.dwSize = sizeof(PROCESSENTRY32);	// set struct size

	if (!Process32First(h_process_snap, &pe32)) {
		printf("[Process32First error id]: %d\r\n", GetLastError());
		CloseHandle(h_process_snap);
		return 0;
	}

	do {
		char process_path[MAX_PATH] = { 0 };
		BOOL bl_Wow64Process = FALSE;
		std::string str_process_name = pe32.szExeFile;
		
		HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (h_process != INVALID_HANDLE_VALUE) {
			// module path is process path
			GetModuleFileNameEx(h_process, NULL, process_path, sizeof(process_path));

			IsWow64Process(h_process, &bl_Wow64Process);
			if (bl_Wow64Process) {
				// is 64 process
				str_process_name += "(32-bit)";
			}
			CloseHandle(h_process);
		}
		printf("%-50s\t%10d\t%s\r\n", str_process_name.c_str(), pe32.th32ProcessID, process_path);

	} while (Process32Next(h_process_snap, &pe32));

	getchar();
	return 0;
}

void KillProcess(CString chProcessName)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,FindProcess(chProcessName.GetBuffer(0)));

	if (hProcess == NULL)
	{
		return;
	}
	TerminateProcess(hProcess, 0);
	CloseHandle(hProcess);

	return;
}
