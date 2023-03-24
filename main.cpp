#include <stdio.h>
#include "NtSocket.h"

int main(int argc, char* argv[])
{
	// get NtDeviceIoControlFile function ptr
	NtDeviceIoControlFile = (unsigned long(__stdcall*)(void*, void*, void*, void*, struct IO_STATUS_BLOCK*, unsigned long, void*, unsigned long, void*, unsigned long))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeviceIoControlFile");
	if (NtDeviceIoControlFile == NULL)
	{
		return 1;
	}

	// get NtCreateFile function ptr
	NtCreateFile = (unsigned long(__stdcall*)(void**, unsigned long, struct OBJECT_ATTRIBUTES*, struct IO_STATUS_BLOCK*, union _LARGE_INTEGER*, unsigned long, unsigned long, unsigned long, unsigned long, void*, unsigned long))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
	if (NtCreateFile == NULL)
	{
		return 1;
	}

	NtSocket socket;

	// 142.250.67.14 in big-endian (network byte order)
	DWORD host = _byteswap_ulong(0x8efa430e);

	// 80 in big-endian (network byte order)
	WORD port = _byteswap_ushort(80); 

	// connect to server
	if (socket.Connect(host, port) != 0)
	{
		// error
		printf("Error: Failed to connect to server\n");
		return 1;
	}

	char getRequest[] = "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n";

	

	if (socket.Send((BYTE*)getRequest, strlen(getRequest)) != 0)
	{
		// error
		printf("Error: Failed to send data to server\n");
		return 1;
	}

	char buf[5000] = { 0 };
	DWORD ret = socket.Recv((BYTE*)&buf, sizeof(buf));
	printf("%s\n", buf);

	return 0;
}
