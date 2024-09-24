#pragma once
#include <iostream>
#include <vector>

#include "WinStruct.h"
#include "ReClassNET_Plugin.hpp"


#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_CE_READMEMORY						CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_WRITEMEMORY					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_QUERYINFORMATIONPROCESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x085e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_RE_QUERY_MEMORY				CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0863, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)



typedef struct _RE_PROCESS_INFORMATION {
	BOOLEAN is_wow64;
	ULONGLONG image_base;
	ULONGLONG peb_address;
	ULONGLONG eprocess;
	WCHAR image_name[260];
}RE_PROCESS_INFORMATION, * PRE_PROCESS_INFORMATION;

typedef struct _RE_QUERY_VIRTUAL_MEMORY
{
	ULONG ProcessId;
	ULONGLONG BaseAddress;
	ULONGLONG AllocationBase;
	ULONG AllocationProtect;
	ULONGLONG RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} RE_QUERY_VIRTUAL_MEMORY, * PRE_QUERY_VIRTUAL_MEMORY;

class CEDriver {
private:
	HANDLE m_hDriver;
	BOOL m_loaded;

	
public:

	ULONG64 vad_root_target;
	static CEDriver& get_istance();

	BOOL load();
	VOID unload();
	BOOL status();

	BOOL read_memory(DWORD process_id, ULONG64 address, PVOID lpBuffer, size_t size_of_data);
	template<typename T> BOOL read_memory(DWORD process_id, ULONG64 address, T* data) {
		return CEDriver::read_memory(process_id, address, data, sizeof T);
	}

	BOOL write_memory(DWORD process_id, ULONG64 address, PVOID lpBuffer, size_t size_of_data);
	template<typename T> BOOL write_memory(DWORD process_id, ULONG64 address, T* data) {
		return CEDriver::write_memory(process_id, address, data, sizeof T);
	}

	BOOL query_process_info(DWORD process_id, RE_PROCESS_INFORMATION& process_info);
	BOOL query_memory(DWORD process_id, ULONG64 address, MEMORY_BASIC_INFORMATION& mbi);
};

extern CEDriver driver;
