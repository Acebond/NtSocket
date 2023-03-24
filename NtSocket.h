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
struct IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG Information;
};

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

class NtSocket;
typedef DWORD (NtSocket::*SendRecvFunc)(BYTE*, DWORD);

class NtSocket {
private:
	HANDLE hSocket = nullptr;
	HANDLE hStatusEvent = nullptr;

	DWORD SocketDriverMsg(ULONG dwIoControlCode, BYTE* pData, ULONG dwLength, ULONG* pdwOutputInformation)
	{
		IO_STATUS_BLOCK IoStatusBlock = { 0 };
		DWORD dwStatus = 0;
		BYTE bOutputBlock[0x10];

		// reset status event
		ResetEvent(this->hStatusEvent);

		// send device control request
		dwStatus = NtDeviceIoControlFile(this->hSocket, this->hStatusEvent, NULL, NULL, 
			&IoStatusBlock, dwIoControlCode, static_cast<PVOID>(pData), dwLength, bOutputBlock, sizeof(bOutputBlock));

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
			*pdwOutputInformation = IoStatusBlock.Information;
		}

		return 0;
	}

	DWORD SendRecvAll(BYTE* pData, DWORD dwLength, SendRecvFunc funcSendRecv)
	{
		BYTE* pCurrDataPtr = pData;
		DWORD dwBytesRemaining = dwLength;

		while (dwBytesRemaining > 0)
		{
			DWORD dwBytesProcessed = (this->*funcSendRecv)(pCurrDataPtr, dwBytesRemaining);

			if (dwBytesProcessed == 0)
			{
				// socket disconnected
				return dwLength - dwBytesRemaining;
			}

			// update values
			pCurrDataPtr += dwBytesProcessed;
			dwBytesRemaining -= dwBytesProcessed;
		}

		return dwLength;
	}

public:
	NtSocket() {
		IO_STATUS_BLOCK IoStatusBlock = { 0 };
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
		UNICODE_STRING ObjectFilePath = { 0 };
		BYTE bExtendedAttributes[] =
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1E, 0x00, 0x41, 0x66, 0x64, 0x4F, 0x70, 0x65, 0x6E, 0x50,
			0x61, 0x63, 0x6B, 0x65, 0x74, 0x58, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x60, 0xEF, 0x3D, 0x47, 0xFE
		};

		// create status event
		hStatusEvent = CreateEventW(NULL, 0, 0, NULL);
		if (hStatusEvent == nullptr)
		{
			// error
			return;
		}

		// set afd endpoint path
		ObjectFilePath.Buffer = const_cast<PWSTR>(L"\\Device\\Afd\\Endpoint");
		ObjectFilePath.Length = static_cast<USHORT>(wcslen(ObjectFilePath.Buffer) * sizeof(wchar_t));
		ObjectFilePath.MaximumLength = ObjectFilePath.Length;

		// initialise object attributes
		ObjectAttributes.Length = sizeof(ObjectAttributes);
		ObjectAttributes.ObjectName = &ObjectFilePath;
		ObjectAttributes.Attributes = 0x40;

		// create socket handle
		DWORD dwStatus = NtCreateFile(&hSocket, 0xC0140000, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 1, 0, bExtendedAttributes, sizeof(bExtendedAttributes));
		if (dwStatus != 0)
		{
			// error
			CloseHandle(hStatusEvent);
			return;
		}
	}

	~NtSocket() {
		if (this->hSocket != nullptr) {
			CloseHandle(this->hSocket);
		}
		if (this->hStatusEvent != nullptr) {
			CloseHandle(this->hStatusEvent);
		}
	}

	// The connect function establishes a connection to the specified dwConnectAddr and wConnectPort.
	// Returns 0 on success and 1 if an error occurs.
	DWORD Connect(DWORD dwConnectAddr, WORD wConnectPort)
	{
		dwConnectAddr = _byteswap_ulong(dwConnectAddr);
		wConnectPort = _byteswap_ushort(wConnectPort);

		NTSockets_BindDataStruct NTSockets_BindData = { 0 };
		NTSockets_ConnectDataStruct NTSockets_ConnectData = { 0 };

		// bind to local port
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
		NTSockets_SendRecvDataStruct NTSockets_SendRecvData = { 0 };
		NTSockets_DataBufferStruct NTSockets_DataBuffer = { 0 };
		DWORD dwBytesSent = 0;

		// set data buffer values
		NTSockets_DataBuffer.dwDataLength = dwLength;
		NTSockets_DataBuffer.pData = pData;

		// send current block
		NTSockets_SendRecvData.pBufferList = &NTSockets_DataBuffer;
		NTSockets_SendRecvData.dwBufferCount = 1;

		if (SocketDriverMsg(0x0001201F, (BYTE*)&NTSockets_SendRecvData, sizeof(NTSockets_SendRecvData), &dwBytesSent) != 0)
		{
			// error
			return 0;
		}
		return dwBytesSent;
	}

	// SendAll() sends exactly dwLength bytes from pData.
	// It returns the number of bytes sent and an error is indicated if the return value != dwLength.
	DWORD SendAll(BYTE* pData, DWORD dwLength) 
	{
		return SendRecvAll(pData, dwLength, &NtSocket::Send);
	}

	// The Recv() function receives data from a connected socket.
	// If no error occurs, Recv() returns the number of bytes received and the buffer pointed to by the pData parameter will contain this data received.
	// If the connection has been closed or an error occurs, the return value is zero.
	DWORD Recv(BYTE* pData, DWORD dwLength)
	{
		NTSockets_SendRecvDataStruct NTSockets_SendRecvData = { 0 };
		NTSockets_DataBufferStruct NTSockets_DataBuffer = { 0 };
		DWORD dwBytesReceived = 0;
		
		// set data buffer values
		NTSockets_DataBuffer.dwDataLength = dwLength;
		NTSockets_DataBuffer.pData = pData;

		// recv current block
		NTSockets_SendRecvData.pBufferList = &NTSockets_DataBuffer;
		NTSockets_SendRecvData.dwBufferCount = 1;
		NTSockets_SendRecvData.dwUnknown1 = 0;
		NTSockets_SendRecvData.dwUnknown2 = 0x20;
		if (SocketDriverMsg(0x00012017, (BYTE*)&NTSockets_SendRecvData, sizeof(NTSockets_SendRecvData), &dwBytesReceived) != 0)
		{
			// error
			return 0;
		}

		return dwBytesReceived;
	}

	// RecvAll() reads exactly dwLength bytes into pData.
	// It returns the number of bytes received and an error is indicated if the return value != dwLength.
	DWORD RecvAll(BYTE* pData, DWORD dwLength)
	{
		return SendRecvAll(pData, dwLength, &NtSocket::Recv);
	}
};
