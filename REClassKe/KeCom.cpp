#include "KeCom.h"


CEDriver& CEDriver::get_istance()
{
	static CEDriver driver;
	return driver;
}

BOOL CEDriver::load()
{
	m_hDriver = CreateFile(L"\\\\?\\ShadowHermes",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	return (m_hDriver == INVALID_HANDLE_VALUE) ? FALSE : TRUE;
}

VOID CEDriver::unload()
{
	if (m_hDriver == INVALID_HANDLE_VALUE)
		CloseHandle(m_hDriver);
}

BOOL CEDriver::status()
{
	return (m_hDriver == INVALID_HANDLE_VALUE) ? FALSE : TRUE;
}

BOOL CEDriver::read_memory(DWORD process_id, ULONG64 address, PVOID lpBuffer, size_t size_of_data)
{
#pragma pack(push, 1)
	struct input
	{
		UINT64 processid;
		UINT64 startaddress;
		WORD bytestoread;
	}inp;
#pragma pack(pop)

	inp.processid = process_id;
	inp.startaddress = address;
	inp.bytestoread = size_of_data;

	DWORD bytesRead;
	if (DeviceIoControl(m_hDriver, IOCTL_CE_READMEMORY, &inp, sizeof(input), lpBuffer, size_of_data, &bytesRead, NULL)) {
		return TRUE;
	}

	return FALSE;
}

BOOL CEDriver::write_memory(DWORD process_id, ULONG64 address, PVOID lpBuffer, size_t size_of_data)
{
#pragma pack(push, 1)
	struct input
	{
		UINT64 processid;
		UINT64 startaddress;
		WORD bytestowrite;
	}inp;
#pragma pack(pop)

	inp.processid = process_id;
	inp.startaddress = address;
	inp.bytestowrite = size_of_data;

	BYTE* buffer = new BYTE[sizeof(input) + size_of_data];

	printf("buffer: 0x%llx", buffer);
	memcpy(buffer, &inp, sizeof(input));
	memcpy(&buffer[sizeof(input)], lpBuffer, size_of_data);


	DWORD bytesRead;
	if (DeviceIoControl(m_hDriver, IOCTL_CE_WRITEMEMORY, buffer, sizeof(input) + size_of_data, buffer, sizeof(input) + size_of_data, &bytesRead, NULL)) {
		return TRUE;
	}

	return FALSE;
}





BOOL CEDriver::query_process_info(DWORD process_id, RE_PROCESS_INFORMATION& process_info)
{
	//if (!m_loaded) return false;

	struct {
		ULONG64 processid;
		ULONG64 ProcessInformationAddress;
		ULONG64 ProcessInformationClass;
		ULONG64 ProcessInformationLength;
	}inp;


	inp.processid = process_id;
	inp.ProcessInformationClass = ProcessBasicInformation;
	inp.ProcessInformationLength = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
	inp.ProcessInformationAddress = 1;

	struct {
		ULONG64 result;
		ULONG64 returnLength;
		char data;
	}outp;


	if (!DeviceIoControl(m_hDriver, IOCTL_CE_QUERYINFORMATIONPROCESS, &inp, sizeof(inp), &outp, sizeof(outp) + inp.ProcessInformationLength, NULL, NULL))
		return false;


	process_info.is_wow64 = (ULONG)((PPROCESS_EXTENDED_BASIC_INFORMATION)&outp.data)->IsWow64Process;
	process_info.peb_address = (ULONG64)((PPROCESS_EXTENDED_BASIC_INFORMATION)&outp.data)->BasicInfo.PebBaseAddress;

	PEB_FULL peb;
	if (!read_memory(process_id, process_info.peb_address, &peb))
		return false;

	process_info.image_base = (ULONG64)peb.ImageBaseAddress;

	RTL_USER_PROCESS_PARAMETERS process_parameters;
	if (!read_memory(process_id, (ULONG64)peb.ProcessParameters, &process_parameters))
		return false;

	LPWSTR image_name = new WCHAR[process_parameters.ImagePathName.Length];

	if (!read_memory(process_id, (ULONG64)process_parameters.ImagePathName.Buffer, (PVOID)image_name, process_parameters.ImagePathName.Length))
		return false;

	memset(process_info.image_name, 0, 260);
	memcpy(process_info.image_name, image_name, process_parameters.ImagePathName.Length);

	return true;
}

BOOL CEDriver::query_memory(DWORD process_id, ULONG64 address, MEMORY_BASIC_INFORMATION& mbi)
{
	if (!m_loaded) return FALSE;

	RE_QUERY_VIRTUAL_MEMORY vquery{};
	vquery.ProcessId = process_id;
	vquery.BaseAddress = (ULONGLONG)address;

	
	if (DeviceIoControl(m_hDriver, IOCTL_CE_RE_QUERY_MEMORY, &vquery, sizeof vquery, &mbi, sizeof mbi, NULL, NULL))
	{
		return TRUE;
	}
	return FALSE;
}



