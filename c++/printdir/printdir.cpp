#include <dirent.h>
#include <sys/types.h>
#include <string>
#include <iostream>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
using namespace std;

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define PORT "8080"

int main(int argc, char *argv[]) {

	DIR *dp = NULL;
	struct dirent *dptr = NULL;

	// Buffer for storing directory path
	char buffer[128];
	memset(buffer,0,sizeof(buffer));

	// Copy path set
	strcpy(buffer,argv[1]);

	// Show argv[1]
	cout << "Directory Path: " << argv[1] << endl;

	// Open directory stream
	if((dp = opendir(argv[1])) == NULL)
	{	
		cout << "Cannot open input directory" << endl;
		exit(1);
	}

/*	else 
	{
		// Check if user supplied '/' at end of directory name
		// Possible underflow; ? strlen = 0
		if(buffer[strlen(buffer)-1] == '/')
			buffer[strlen(buffer)-1] = '/0';
	} */


	// ================================================================SOCKET

	// Debug
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

	// ======================================================================
	
	// Print directory contents
	cout << "Directory Contents" << endl;
	while(dptr = readdir(dp))
	{
		cout << dptr -> d_name << endl;
		sendbuf = dptr -> d_name;
		iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
		if(iResult == SOCKET_ERROR) {
			cout << "send failed with error: " << WSAGetLastError();
			WSACleanup();
			return 1;
		}
	}

	// Close directory stream
	closedir(dp);
	
	// Close socket
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}
