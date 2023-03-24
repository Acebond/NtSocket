#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#define AFD_BIND 0
#define AFD_CONNECT 1

#define FSCTL_AFD_BASE FILE_DEVICE_NETWORK
#define _AFD_CONTROL_CODE(Operation,Method) ((FSCTL_AFD_BASE)<<12 | (Operation<<2) | Method)

#define IOCTL_AFD_BIND _AFD_CONTROL_CODE(AFD_BIND, METHOD_NEITHER)
#define IOCTL_AFD_CONNECT _AFD_CONTROL_CODE(AFD_CONNECT, METHOD_NEITHER)


DWORD(WINAPI* NtDeviceIoControlFile)(HANDLE FileHandle, HANDLE Event, VOID* ApcRoutine, PVOID ApcContext, struct IO_STATUS_BLOCK* IoStatusBlock,
	ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

DWORD(WINAPI* NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, struct OBJECT_ATTRIBUTES* ObjectAttributes,
	struct IO_STATUS_BLOCK* IoStatusBlock, LARGE_INTEGER* AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);



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

class NtSocket {
private:
	HANDLE hSocket = NULL;
	HANDLE hStatusEvent = NULL;

	DWORD SocketDriverMsg(DWORD dwIoControlCode, BYTE* pData, DWORD dwLength, DWORD* pdwOutputInformation)
	{
		IO_STATUS_BLOCK IoStatusBlock;
		DWORD dwStatus = 0;
		BYTE bOutputBlock[0x10];

		// reset status event
		ResetEvent(this->hStatusEvent);

		// send device control request
		IoStatusBlock.Status = 0;
		IoStatusBlock.Information = NULL;
		dwStatus = NtDeviceIoControlFile(this->hSocket, this->hStatusEvent, NULL, NULL, &IoStatusBlock, dwIoControlCode, (void*)pData, dwLength, bOutputBlock, sizeof(bOutputBlock));
		if (dwStatus == STATUS_PENDING)
		{
			// response pending - wait for event
			if (WaitForSingleObject(this->hStatusEvent, INFINITE) != WAIT_OBJECT_0)
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
public:
	NtSocket() {
		IO_STATUS_BLOCK IoStatusBlock;
		struct OBJECT_ATTRIBUTES ObjectAttributes;
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
		hStatusEvent = CreateEvent(NULL, 0, 0, NULL);
		if (hStatusEvent == NULL)
		{
			// error
			// return 1;
		}

		// set afd endpoint path
		memset((void*)&ObjectFilePath, 0, sizeof(ObjectFilePath));
		ObjectFilePath.Buffer = const_cast<PWSTR>(L"\\Device\\Afd\\Endpoint");
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
			CloseHandle(hStatusEvent);
			//return 1;
		}

		// initialise SocketData object
		//memset((void*)&SocketData, 0, sizeof(SocketData));
		//SocketData.hSocket = hSocket;
		//SocketData.hStatusEvent = hEvent;

		// store socket data
		//memcpy((void*)pSocketData, (void*)&SocketData, sizeof(SocketData));

		//return 0;
	}

	~NtSocket() {
		CloseHandle(this->hSocket);
		CloseHandle(this->hStatusEvent);
	}

	DWORD Connect(DWORD dwConnectAddr, WORD wConnectPort)
	{
		struct NTSockets_BindDataStruct NTSockets_BindData;
		struct NTSockets_ConnectDataStruct NTSockets_ConnectData;

		// bind to local port
		memset((void*)&NTSockets_BindData, 0, sizeof(NTSockets_BindData));
		NTSockets_BindData.dwUnknown1 = 2;
		NTSockets_BindData.SockAddr.sin_family = AF_INET;
		NTSockets_BindData.SockAddr.sin_addr.s_addr = INADDR_ANY;
		NTSockets_BindData.SockAddr.sin_port = 0;
		if (SocketDriverMsg(IOCTL_AFD_BIND, (BYTE*)&NTSockets_BindData, sizeof(NTSockets_BindData), NULL) != 0)
		{
			// error
			return 1;
		}

		// connect to remote port
		memset((void*)&NTSockets_ConnectData, 0, sizeof(NTSockets_ConnectData));
		NTSockets_ConnectData.dwUnknown1 = 0;
		NTSockets_ConnectData.dwUnknown2 = 0;
		NTSockets_ConnectData.dwUnknown3 = 0;
		NTSockets_ConnectData.SockAddr.sin_family = AF_INET;
		NTSockets_ConnectData.SockAddr.sin_addr.s_addr = dwConnectAddr;
		NTSockets_ConnectData.SockAddr.sin_port = wConnectPort;
		if (SocketDriverMsg(IOCTL_AFD_CONNECT, (BYTE*)&NTSockets_ConnectData, sizeof(NTSockets_ConnectData), NULL) != 0)
		{
			// error
			return 1;
		}

		return 0;
	}

	DWORD Send(BYTE* pData, DWORD dwLength)
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
			if (SocketDriverMsg(0x0001201F, (BYTE*)&NTSockets_SendRecvData, sizeof(NTSockets_SendRecvData), &dwBytesSent) != 0)
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

	DWORD Recv(BYTE* pData, DWORD dwLength)
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
			if (SocketDriverMsg(0x00012017, (BYTE*)&NTSockets_SendRecvData, sizeof(NTSockets_SendRecvData), &dwBytesReceived) != 0)
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


};
