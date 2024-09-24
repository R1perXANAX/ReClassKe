#include <Windows.h>
#include "KeCom.h"
#include "REClassKe.h"

CEDriver driver;



enum class Platform
{
	Unknown,
	X86,
	X64
};

Platform GetProcessPlatform(HANDLE process)
{
	static USHORT processorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
	if (processorArchitecture == PROCESSOR_ARCHITECTURE_UNKNOWN)
	{
		SYSTEM_INFO info = {};
		GetNativeSystemInfo(&info);

		processorArchitecture = info.wProcessorArchitecture;
	}

	switch (processorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		return Platform::X86;
	case PROCESSOR_ARCHITECTURE_AMD64:
		auto isWow64 = FALSE;
		if (IsWow64Process(process, &isWow64))
		{
			return isWow64 ? Platform::X86 : Platform::X64;
		}

#ifdef RECLASSNET64
		return Platform::X64;
#else
		return Platform::X86;
#endif
	}
	return Platform::Unknown;
}

extern "C" RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess desiredAccess)
{
	printf("[+]Opening process with pid: %d\n", (DWORD)id);
	return id;
}

extern "C" bool RC_CallConv IsProcessValid(RC_Pointer id)
{
	if (id == nullptr)
	{
		return false;
	}

	return true;
}

extern "C" void RC_CallConv CloseRemoteProcess(RC_Pointer handle)
{
	return;
}

/// <summary>Enumerate all processes on the system.</summary>
/// <param name="callbackProcess">The callback for a process.</param>
extern "C" void RC_CallConv EnumerateProcesses(EnumerateProcessCallback callbackProcess)
{
	if (callbackProcess)
	{
		HANDLE snapshot_handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot_handle != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32W proc = { 0 };
			proc.dwSize = sizeof(proc);
			::Process32FirstW(snapshot_handle, &proc);

			do
			{
				if (proc.th32ProcessID == 0 || proc.th32ProcessID == 4)
					continue;

				//system process to consume (compressing) physical pages not used
				if (_wcsicmp(proc.szExeFile, L"Memory Compression") == 0)
					continue;

				EnumerateProcessData data = { 0 };
				RE_PROCESS_INFORMATION info = { 0 };

				if (driver.query_process_info(proc.th32ProcessID, info) &&
#ifdef RECLASSNET64

					!info.is_wow64
#else
					info.IsWow64
#endif
					)
				{
					data.Id = proc.th32ProcessID;
					std::memcpy(data.Name, proc.szExeFile, PATH_MAXIMUM_LENGTH * sizeof(RC_UnicodeChar));
					std::memcpy(data.Path, info.image_name, PATH_MAXIMUM_LENGTH * sizeof(RC_UnicodeChar));

					callbackProcess(&data);
				}
			} while (::Process32NextW(snapshot_handle, &proc));

			::CloseHandle(snapshot_handle);
		}
	}

}



extern "C" void RC_CallConv EnumerateRemoteSectionsAndModules(RC_Pointer handle, EnumerateRemoteSectionsCallback callbackSection, EnumerateRemoteModulesCallback callbackModule)
{
	if (callbackSection == nullptr && callbackModule == nullptr)
		return;

	DWORD process_id = (DWORD)handle;

	std::vector<EnumerateRemoteSectionData> memory_sections{};

	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	memInfo.RegionSize = 0x1000;
	uintptr_t current_address = 0;

	while (driver.query_memory(process_id, current_address, memInfo) && (current_address + memInfo.RegionSize) > current_address)
	{
		if (memInfo.State == MEM_COMMIT)
		{
			EnumerateRemoteSectionData section = { 0 };
			section.BaseAddress = memInfo.BaseAddress;
			section.Size = memInfo.RegionSize;

			section.Protection = SectionProtection::NoAccess;
			if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE) section.Protection |= SectionProtection::Execute;
			if ((memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ) section.Protection |= SectionProtection::Execute | SectionProtection::Read;
			if ((memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) section.Protection |= SectionProtection::Execute | SectionProtection::Read | SectionProtection::Write;
			if ((memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_READWRITE) section.Protection |= SectionProtection::Execute | SectionProtection::Read | SectionProtection::CopyOnWrite;
			if ((memInfo.Protect & PAGE_READONLY) == PAGE_READONLY) section.Protection |= SectionProtection::Read;
			if ((memInfo.Protect & PAGE_READWRITE) == PAGE_READWRITE) section.Protection |= SectionProtection::Read | SectionProtection::Write;
			if ((memInfo.Protect & PAGE_WRITECOPY) == PAGE_WRITECOPY) section.Protection |= SectionProtection::Read | SectionProtection::CopyOnWrite;
			if ((memInfo.Protect & PAGE_GUARD) == PAGE_GUARD) section.Protection |= SectionProtection::Guard;

			switch (memInfo.Type)
			{
			case MEM_IMAGE:
				section.Type = SectionType::Image;
				break;
			case MEM_MAPPED:
				section.Type = SectionType::Mapped;
				break;
			case MEM_PRIVATE:
				section.Type = SectionType::Private;
				break;
			default:
				break;
			}

			section.Category = section.Type == SectionType::Private ? SectionCategory::HEAP : SectionCategory::Unknown;

			memory_sections.push_back(section);
		}
		current_address = reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + memInfo.RegionSize;
	}

	HANDLE module_snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (module_snapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32W module_entry = { 0 };
		module_entry.dwSize = sizeof MODULEENTRY32W;
		::Module32FirstW(module_snapshot, &module_entry);

		do
		{
			if (callbackModule != nullptr)
			{
				EnumerateRemoteModuleData data = { 0 };
				data.BaseAddress = module_entry.modBaseAddr;
				data.Size = module_entry.modBaseSize;
				std::memcpy(data.Path, module_entry.szExePath, PATH_MAXIMUM_LENGTH * sizeof(RC_UnicodeChar));
				callbackModule(&data);
			}

			if (callbackSection != nullptr)
			{
				auto module_first_section = std::lower_bound(memory_sections.begin(), memory_sections.end(), (LPVOID)module_entry.modBaseAddr,
					[](const EnumerateRemoteSectionData& lhs, const LPVOID& rhs) { return lhs.BaseAddress < rhs; });

				IMAGE_DOS_HEADER dos_head = { 0 };
				IMAGE_NT_HEADERS32 nt_heads = { 0 };

				driver.read_memory(process_id, (DWORD_PTR)module_entry.modBaseAddr, &dos_head);
				driver.read_memory(process_id, (DWORD_PTR)module_entry.modBaseAddr + dos_head.e_lfanew, &nt_heads);

				std::vector<IMAGE_SECTION_HEADER> sections{ nt_heads.FileHeader.NumberOfSections };
				LPVOID section_start_address = module_entry.modBaseAddr + dos_head.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + nt_heads.FileHeader.SizeOfOptionalHeader;
				driver.read_memory(process_id, (DWORD_PTR)section_start_address, sections.data(), sizeof(IMAGE_SECTION_HEADER) * nt_heads.FileHeader.NumberOfSections);

				for (auto&& section : sections)
				{
					const uintptr_t section_address = (uintptr_t)module_entry.modBaseAddr + section.VirtualAddress;

					for (auto current_section = module_first_section; current_section != memory_sections.end(); ++current_section)
					{
						if (section_address >= (uintptr_t)current_section->BaseAddress && section_address < (uintptr_t)current_section->BaseAddress + current_section->Size)
						{
							// Copy the name because it is not null padded.
							char section_name_buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
							memcpy(section_name_buffer, section.Name, IMAGE_SIZEOF_SHORT_NAME);

							if (section.Characteristics & IMAGE_SCN_CNT_CODE)
								current_section->Category = SectionCategory::CODE;
							else if (section.Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA))
								current_section->Category = SectionCategory::DATA;

							MultiByteToUnicode(section_name_buffer, current_section->Name, IMAGE_SIZEOF_SHORT_NAME);
							memcpy(current_section->ModulePath, module_entry.szExePath, PATH_MAXIMUM_LENGTH);

							break;
						}
					}
				}
			}
		} while (::Module32NextW(module_snapshot, &module_entry));

		::CloseHandle(module_snapshot);

		if (callbackSection != nullptr)
			for (auto&& section : memory_sections)
				callbackSection(&section);
	}
}


/// <summary>Reads memory of the remote process.</summary>
/// <param name="handle">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="address">The address to read from.</param>
/// <param name="buffer">The buffer to read into.</param>
/// <param name="offset">The offset into the buffer.</param>
/// <param name="size">The number of bytes to read.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv ReadRemoteMemory(RC_Pointer id, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	if (!driver.status())
		return false;

	return driver.read_memory((DWORD)id, (ULONG64)address, (PVOID)((ULONG64)buffer + (DWORD_PTR)offset), size);
}

/// <summary>Writes memory to the remote process.</summary>
/// <param name="process">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="address">The address to write to.</param>
/// <param name="buffer">The buffer to write.</param>
/// <param name="offset">The offset into the buffer.</param>
/// <param name="size">The number of bytes to write.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv WriteRemoteMemory(RC_Pointer id, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	if (!driver.status())
		return false;

	return driver.write_memory((DWORD)id, (DWORD_PTR)address, (PVOID)((DWORD_PTR)buffer + (DWORD_PTR)offset), size);
}

/// <summary>Control the remote process (Pause, Resume, Terminate).</summary>
/// <param name="handle">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="action">The action to perform.</param>
extern "C" void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action)
{
	return;
	// Perform the desired action on the remote process.
}

/// <summary>Attach a debugger to the process.</summary>
/// <param name="id">The identifier of the process returned by EnumerateProcesses.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv AttachDebuggerToProcess(RC_Pointer id)
{
	// Attach a debugger to the remote process.
	return false;
}

/// <summary>Detach a debugger from the remote process.</summary>
/// <param name="id">The identifier of the process returned by EnumerateProcesses.</param>
extern "C" void RC_CallConv DetachDebuggerFromProcess(RC_Pointer id)
{
	return;
	// Detach the debugger.
}

/// <summary>Wait for a debug event within the given timeout.</summary>
/// <param name="evt">[out] The occured debug event.</param>
/// <param name="timeoutInMilliseconds">The timeout in milliseconds.</param>
/// <returns>True if an event occured within the given timeout, false if not.</returns>
extern "C" bool RC_CallConv AwaitDebugEvent(DebugEvent * evt, int timeoutInMilliseconds)
{
	// Wait for a debug event.
	return false;
}

/// <summary>Handles the debug event described by evt.</summary>
/// <param name="evt">[in] The (modified) event returned by AwaitDebugEvent.</param>
extern "C" void RC_CallConv HandleDebugEvent(DebugEvent * evt)
{
	// Handle the debug event.
}

/// <summary>Sets a hardware breakpoint.</summary>
/// <param name="processId">The identifier of the process returned by EnumerateProcesses.</param>
/// <param name="address">The address of the breakpoint.</param>
/// <param name="reg">The register to use.</param>
/// <param name="type">The type of the breakpoint.</param>
/// <param name="size">The size of the breakpoint.</param>
/// <param name="set">True to set the breakpoint, false to remove it.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv SetHardwareBreakpoint(RC_Pointer id, RC_Pointer address, HardwareBreakpointRegister reg, HardwareBreakpointTrigger type, HardwareBreakpointSize size, bool set)
{
	// Set a hardware breakpoint with the given parameters.
	return false;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        driver = CEDriver::get_istance();
        driver.load();
        if (driver.status())
            printf("[+]Connected to CE Driver\n");
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH: {
        driver.unload();
        break;
    }
        
    }
    return TRUE;
}

