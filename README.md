# REClass.NET Memory Access Plugin

A plugin for **REClass.NET** that enables reading and writing memory from the kernel using the Cheat Engine driver. This project also modifies the Cheat Engine driver to add an IOCTL for calling `ZwQueryVirtualMemory`, making it easier to retrieve memory information.

## Features

- Read and write memory directly from the kernel.
- Enhanced memory information retrieval through the `ZwQueryVirtualMemory` function.
- Tested on Windows 10 version 20H2.

## Installation

### Requirements

- **REClass.NET**
- **Cheat Engine** driver
- Windows 10 (20H2)

### Steps to Install

1. **Integrate the IOCTL Code:**
   To enable the memory query functionality, add the following code snippet to the Cheat Engine driver. If you wish to exclude this functionality, you may omit the corresponding section from your project.

   ```c
   case IOCTL_CE_RE_QUERY_MEMORY: {
       struct {
           ULONG ProcessId;
           ULONGLONG BaseAddress;
           ULONGLONG AllocationBase;
           ULONG AllocationProtect;
           ULONGLONG RegionSize;
           ULONG State;
           ULONG Protect;
           ULONG Type;
       }*pinp = Irp->AssociatedIrp.SystemBuffer;

       if (!pinp) {
           ntStatus = STATUS_NOT_FOUND;
           break;
       }

       MEMORY_BASIC_INFORMATION outp;
       RtlZeroMemory(&outp, sizeof(outp));

       PEPROCESS targetProcess; 

       if (NT_SUCCESS(PsLookupProcessByProcessId(pinp->ProcessId, &targetProcess))) {
           KeAttachProcess(targetProcess);
           ntStatus = ZwQueryVirtualMemory(ZwCurrentProcess(), pinp->BaseAddress, MemoryBasicInformation, &outp, sizeof(outp), NULL);
           KeDetachProcess();
           ObDereferenceObject(targetProcess);
       }

       RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &outp, sizeof(outp));
   }
  ```
