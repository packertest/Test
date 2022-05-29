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
