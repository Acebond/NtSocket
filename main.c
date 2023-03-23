#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

#define AFD_BIND 0
#define AFD_CONNECT 1

#define FSCTL_AFD_BASE FILE_DEVICE_NETWORK
#define _AFD_CONTROL_CODE(Operation,Method) ((FSCTL_AFD_BASE)<<12 | (Operation<<2) | Method)

#define IOCTL_AFD_BIND _AFD_CONTROL_CODE(AFD_BIND, METHOD_NEITHER)
#define IOCTL_AFD_CONNECT _AFD_CONTROL_CODE(AFD_CONNECT, METHOD_NEITHER)

struct NTSockets_SocketDataStruct
{
	HANDLE hSocket;
	HANDLE hStatusEvent;
};

typedef struct NTSockets_SocketDataStruct NTSockets_SocketDataStruct;

// See https://github.com/reactos/reactos/blob/master/sdk/include/psdk/winternl.h
//typedef struct _IO_STATUS_BLOCK {
//	union {
//		NTSTATUS Status;
//		PVOID Pointer;
//	};
//
//	ULONG_PTR Information;
//} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

struct IO_STATUS_BLOCK
{
	union
	{
		DWORD Status;
		PVOID Pointer;
	};

	DWORD* Information;
};

typedef struct IO_STATUS_BLOCK IO_STATUS_BLOCK;

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};


struct OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	struct UNICODE_STRING* ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
};

struct NTSockets_BindDataStruct
{
	DWORD dwUnknown1;
	struct sockaddr_in SockAddr;
};

struct NTSockets_ConnectDataStruct
{
	DWORD_PTR  dwUnknown1;
	DWORD_PTR  dwUnknown2;
	DWORD_PTR  dwUnknown3;
	struct sockaddr_in SockAddr;
};

struct NTSockets_DataBufferStruct
{
	DWORD dwDataLength;
	BYTE* pData;
};

struct NTSockets_SendRecvDataStruct
{
	struct NTSockets_DataBufferStruct* pBufferList;
	DWORD dwBufferCount;
	DWORD dwUnknown1;
	DWORD dwUnknown2;
};


DWORD(WINAPI* NtDeviceIoControlFile)(HANDLE FileHandle, HANDLE Event, VOID* ApcRoutine, PVOID ApcContext, struct IO_STATUS_BLOCK* IoStatusBlock, 
	ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

DWORD(WINAPI* NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, struct OBJECT_ATTRIBUTES* ObjectAttributes, 
	struct IO_STATUS_BLOCK* IoStatusBlock, LARGE_INTEGER* AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);


WORD my_htons(WORD x)
{
	return _byteswap_ushort(x);
}

DWORD NTSockets_CreateTcpSocket(struct NTSockets_SocketDataStruct* pSocketData)
{
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE hEvent = NULL;
	HANDLE hSocket = NULL;
	struct OBJECT_ATTRIBUTES ObjectAttributes;
	struct NTSockets_SocketDataStruct SocketData;
	struct UNICODE_STRING ObjectFilePath;
	DWORD dwStatus = 0;
	BYTE bExtendedAttributes[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1E, 0x00, 0x41, 0x66, 0x64, 0x4F, 0x70, 0x65, 0x6E, 0x50,
		0x61, 0x63, 0x6B, 0x65, 0x74, 0x58, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x60, 0xEF, 0x3D, 0x47, 0xFE
	};

	// create status event
	hEvent = CreateEvent(NULL, 0, 0, NULL);
	if (hEvent == NULL)
	{
		// error
		return 1;
	}

	// set afd endpoint path
	memset((void*)&ObjectFilePath, 0, sizeof(ObjectFilePath));
	ObjectFilePath.Buffer = L"\\Device\\Afd\\Endpoint";
	ObjectFilePath.Length = wcslen(ObjectFilePath.Buffer) * sizeof(wchar_t);
	ObjectFilePath.MaximumLength = ObjectFilePath.Length;

	// initialise object attributes
	memset((void*)&ObjectAttributes, 0, sizeof(ObjectAttributes));
	ObjectAttributes.Length = sizeof(ObjectAttributes);
	ObjectAttributes.ObjectName = &ObjectFilePath;
	ObjectAttributes.Attributes = 0x40;

	// create socket handle
	IoStatusBlock.Status = 0;
	IoStatusBlock.Information = NULL;
	dwStatus = NtCreateFile(&hSocket, 0xC0140000, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 1, 0, bExtendedAttributes, sizeof(bExtendedAttributes));
	if (dwStatus != 0)
	{
		// error
		CloseHandle(hEvent);

		return 1;
	}

	// initialise SocketData object
	memset((void*)&SocketData, 0, sizeof(SocketData));
	SocketData.hSocket = hSocket;
	SocketData.hStatusEvent = hEvent;

	// store socket data
	memcpy((void*)pSocketData, (void*)&SocketData, sizeof(SocketData));

	return 0;
}

DWORD NTSockets_SocketDriverMsg(NTSockets_SocketDataStruct* pSocketData, DWORD dwIoControlCode, BYTE* pData, DWORD dwLength, DWORD* pdwOutputInformation)
{
	IO_STATUS_BLOCK IoStatusBlock;
	DWORD dwStatus = 0;
	BYTE bOutputBlock[0x10];

	// reset status event
	ResetEvent(pSocketData->hStatusEvent);

	// send device control request
	IoStatusBlock.Status = 0;
	IoStatusBlock.Information = NULL;
	dwStatus = NtDeviceIoControlFile(pSocketData->hSocket, pSocketData->hStatusEvent, NULL, NULL, &IoStatusBlock, dwIoControlCode, (void*)pData, dwLength, bOutputBlock, sizeof(bOutputBlock));
	if (dwStatus == STATUS_PENDING)
	{
		// response pending - wait for event
		if (WaitForSingleObject(pSocketData->hStatusEvent, INFINITE) != WAIT_OBJECT_0)
		{
			// error
			return 1;
		}

		// complete - get final status code
		dwStatus = IoStatusBlock.Status;
	}

	// check for errors
	if (dwStatus != 0)
	{
		// error
		return 1;
	}

	if (pdwOutputInformation != NULL)
	{
		// store output info
		*pdwOutputInformation = (DWORD)IoStatusBlock.Information;
	}

	return 0;
}

DWORD NTSockets_ConvertIP(char* pIP, DWORD* pdwAddr)
{
	char szCurrOctet[8];
	DWORD dwCurrOctetIndex = 0;
	DWORD dwCompletedOctetCount = 0;
	char* pCurrByte = NULL;
	DWORD dwEndOfOctet = 0;
	DWORD dwEndOfString = 0;
	DWORD dwOctet = 0;
	BYTE bOctets[4];
	DWORD dwAddr = 0;

	// read IP string
	memset(szCurrOctet, 0, sizeof(szCurrOctet));
	dwCurrOctetIndex = 0;
	pCurrByte = pIP;
	for (;;)
	{
		// process current character
		dwEndOfOctet = 0;
		if (*pCurrByte == '\0')
		{
			// end of string
			dwEndOfOctet = 1;
			dwEndOfString = 1;
		}
		else if (*pCurrByte == '.')
		{
			// end of octet
			dwEndOfOctet = 1;
		}
		else
		{
			// ensure this character is a number
			if (*pCurrByte >= '0' && *pCurrByte <= '9')
			{
				if (dwCurrOctetIndex > 2)
				{
					// invalid ip
					return 1;
				}

				// store current character
				szCurrOctet[dwCurrOctetIndex] = *pCurrByte;
				dwCurrOctetIndex++;
			}
			else
			{
				// invalid ip
				return 1;
			}
		}

		// check if the current octet is complete
		if (dwEndOfOctet != 0)
		{
			if (dwCurrOctetIndex == 0)
			{
				// invalid ip
				return 1;
			}

			// convert octet string to integer
			dwOctet = atoi(szCurrOctet);
			if (dwOctet > 255)
			{
				// invalid ip
				return 1;
			}

			// already read 4 octets
			if (dwCompletedOctetCount >= 4)
			{
				// invalid ip
				return 1;
			}

			// store current octet
			bOctets[dwCompletedOctetCount] = (BYTE)dwOctet;

			// current octet complete
			dwCompletedOctetCount++;

			if (dwEndOfString != 0)
			{
				// end of string
				break;
			}

			// reset szCurrOctet string
			memset(szCurrOctet, 0, sizeof(szCurrOctet));
			dwCurrOctetIndex = 0;
		}

		// move to the next character
		pCurrByte++;
	}

	// ensure 4 octets were found
	if (dwCompletedOctetCount != 4)
	{
		// invalid string
		return 1;
	}

	// store octets in dword value
	memcpy((void*)&dwAddr, bOctets, 4);

	// store value
	*pdwAddr = dwAddr;

	return 0;
}

DWORD NTSockets_Connect(NTSockets_SocketDataStruct* pSocketData, char* pIP, WORD wPort)
{
	struct NTSockets_BindDataStruct NTSockets_BindData;
	struct NTSockets_ConnectDataStruct NTSockets_ConnectData;
	WORD wConnectPort = 0;
	DWORD dwConnectAddr = 0;

	// bind to local port
	memset((void*)&NTSockets_BindData, 0, sizeof(NTSockets_BindData));
	NTSockets_BindData.dwUnknown1 = 2;
	NTSockets_BindData.SockAddr.sin_family = AF_INET;
	NTSockets_BindData.SockAddr.sin_addr.s_addr = INADDR_ANY;
	NTSockets_BindData.SockAddr.sin_port = 0;
	if (NTSockets_SocketDriverMsg(pSocketData, IOCTL_AFD_BIND, (BYTE*)&NTSockets_BindData, sizeof(NTSockets_BindData), NULL) != 0)
	{
		// error
		return 1;
	}

	// read connection ip
	if (NTSockets_ConvertIP(pIP, &dwConnectAddr) != 0)
	{
		// error
		return 1;
	}

	// use network byte order for connection port
	// wConnectPort = NTSockets_Swap16BitByteOrder(wPort);
	wConnectPort = my_htons(wPort);

	// connect to remote port
	memset((void*)&NTSockets_ConnectData, 0, sizeof(NTSockets_ConnectData));
	NTSockets_ConnectData.dwUnknown1 = 0;
	NTSockets_ConnectData.dwUnknown2 = 0;
	NTSockets_ConnectData.dwUnknown3 = 0;
	NTSockets_ConnectData.SockAddr.sin_family = AF_INET;
	NTSockets_ConnectData.SockAddr.sin_addr.s_addr = dwConnectAddr;
	NTSockets_ConnectData.SockAddr.sin_port = wConnectPort;
	if (NTSockets_SocketDriverMsg(pSocketData, IOCTL_AFD_CONNECT, (BYTE*)&NTSockets_ConnectData, sizeof(NTSockets_ConnectData), NULL) != 0)
	{
		// error
		return 1;
	}

	return 0;
}

DWORD NTSockets_Send(NTSockets_SocketDataStruct* pSocketData, BYTE* pData, DWORD dwLength)
{
	struct NTSockets_SendRecvDataStruct NTSockets_SendRecvData;
	struct NTSockets_DataBufferStruct NTSockets_DataBuffer;
	DWORD dwBytesSent = 0;
	BYTE* pCurrSendPtr = NULL;
	DWORD dwBytesRemaining = 0;

	// set initial values
	pCurrSendPtr = pData;
	dwBytesRemaining = dwLength;

	// send data
	for (;;)
	{
		if (dwBytesRemaining == 0)
		{
			// finished
			break;
		}

		// set data buffer values
		memset((void*)&NTSockets_DataBuffer, 0, sizeof(NTSockets_DataBuffer));
		NTSockets_DataBuffer.dwDataLength = dwBytesRemaining;
		NTSockets_DataBuffer.pData = pCurrSendPtr;

		// send current block
		memset((void*)&NTSockets_SendRecvData, 0, sizeof(NTSockets_SendRecvData));
		NTSockets_SendRecvData.pBufferList = &NTSockets_DataBuffer;
		NTSockets_SendRecvData.dwBufferCount = 1;
		NTSockets_SendRecvData.dwUnknown1 = 0;
		NTSockets_SendRecvData.dwUnknown2 = 0;
		if (NTSockets_SocketDriverMsg(pSocketData, 0x0001201F, (BYTE*)&NTSockets_SendRecvData, sizeof(NTSockets_SendRecvData), &dwBytesSent) != 0)
		{
			// error
			return 1;
		}

		if (dwBytesSent == 0)
		{
			// socket disconnected
			return 1;
		}

		// update values
		pCurrSendPtr += dwBytesSent;
		dwBytesRemaining -= dwBytesSent;
	}

	return 0;
}

DWORD NTSockets_Recv(NTSockets_SocketDataStruct* pSocketData, BYTE* pData, DWORD dwLength)
{
	struct NTSockets_SendRecvDataStruct NTSockets_SendRecvData;
	struct NTSockets_DataBufferStruct NTSockets_DataBuffer;
	DWORD dwBytesReceived = 0;
	BYTE* pCurrRecvPtr = NULL;
	DWORD dwBytesRemaining = 0;

	// set initial values
	pCurrRecvPtr = pData;
	dwBytesRemaining = dwLength;

	// send data
	for (;;)
	{
		if (dwBytesRemaining == 0)
		{
			// finished
			break;
		}

		// set data buffer values
		memset((void*)&NTSockets_DataBuffer, 0, sizeof(NTSockets_DataBuffer));
		NTSockets_DataBuffer.dwDataLength = dwBytesRemaining;
		NTSockets_DataBuffer.pData = pCurrRecvPtr;

		// recv current block
		memset((void*)&NTSockets_SendRecvData, 0, sizeof(NTSockets_SendRecvData));
		NTSockets_SendRecvData.pBufferList = &NTSockets_DataBuffer;
		NTSockets_SendRecvData.dwBufferCount = 1;
		NTSockets_SendRecvData.dwUnknown1 = 0;
		NTSockets_SendRecvData.dwUnknown2 = 0x20;
		if (NTSockets_SocketDriverMsg(pSocketData, 0x00012017, (BYTE*)&NTSockets_SendRecvData, sizeof(NTSockets_SendRecvData), &dwBytesReceived) != 0)
		{
			// error
			return 1;
		}

		if (dwBytesReceived == 0)
		{
			// socket disconnected
			return 1;
		}

		// update values
		pCurrRecvPtr += dwBytesReceived;
		dwBytesRemaining -= dwBytesReceived;
	}

	return 0;
}

DWORD NTSockets_CloseSocket(NTSockets_SocketDataStruct* pSocketData)
{
	// close handles
	CloseHandle(pSocketData->hSocket);
	CloseHandle(pSocketData->hStatusEvent);

	return 0;
}

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

	NTSockets_SocketDataStruct SocketData;
	if (NTSockets_CreateTcpSocket(&SocketData) != 0)
	{
		printf("Error: Failed to create TCP socket\n");
		return 1;
	}

	char* host = "142.250.67.14";
	WORD port = 80;

	// connect to server
	if (NTSockets_Connect(&SocketData, host, port) != 0)
	{
		// error
		printf("Error: Failed to connect to server\n");
		NTSockets_CloseSocket(&SocketData);

		return 1;
	}

	char getRequest[] = "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n";

	if (NTSockets_Send(&SocketData, (BYTE*)getRequest, strlen(getRequest)) != 0)
	{
		// error
		printf("Error: Failed to send data to server\n");
		NTSockets_CloseSocket(&SocketData);

		return 1;
	}

	char buf[5000] = { 0 };
	DWORD ret = NTSockets_Recv(&SocketData, (BYTE*)&buf, sizeof(buf));
	printf("%s\n", buf);

	NTSockets_CloseSocket(&SocketData);
	return 0;
}
