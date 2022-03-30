#include <ntddk.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <intrin.h>
#include <ntstrsafe.h>


PDEVICE_OBJECT myDevice;
PDRIVER_DISPATCH originalDeviceControl;

#define SIOCTL_TYPE 40000

#define IOCTL_RESPONSE\
 CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


typedef struct
{
	PIO_COMPLETION_ROUTINE OldRoutine;
	PVOID OldContext;
	ULONG OutputBufferLength;
	PVOID SystemBuffer;
}REQUEST_STRUCT;


NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID* Object
);

extern POBJECT_TYPE* IoDriverObjectType;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	void* NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

int CheckForHook(void)
{
	int foundHook = 0;

	UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
	PDRIVER_OBJECT driverObject = 0;
	NTSTATUS status = ObReferenceObjectByName(
		&driverName,
		OBJ_CASE_INSENSITIVE,
		0,
		0,
		*IoDriverObjectType,
		KernelMode,
		0,
		(PVOID*)(&driverObject)
	);

	if (!driverObject || !NT_SUCCESS(status))
	{
		return foundHook;
	}

	int func;
	KLDR_DATA_TABLE_ENTRY* entry = (KLDR_DATA_TABLE_ENTRY*)driverObject->DriverSection;


	// we really should check .text section to be sure or any executable sections
	unsigned __int64 baseOfDriver = (unsigned __int64)entry->DllBase;
	unsigned __int64 sizeOfImage = (unsigned __int64)entry->SizeOfImage;

	for (func = 0; func < IRP_MJ_MAXIMUM_FUNCTION; ++func)
	{
		unsigned __int64 function = (unsigned __int64)driverObject->MajorFunction[func];

		// someone hooked a callback
		if (function < baseOfDriver || function > (baseOfDriver + sizeOfImage))
		{
			foundHook = func + 1;

			break;
		}
	}

	// while range hook checks are great, if we want to detect the malicious replacement of say driver section we could probably use a checksum on the small pieces of the file and compare
	// alterntively we could check the actual kldr entries themselves and make sure that what we're getting makes sense
	// there are of course other ways

	ObDereferenceObject(driverObject);

	return foundHook;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT deviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObject);

	PIO_STACK_LOCATION pIoStackLocation;
	PCHAR responseMsg = NULL;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	char buffer[256];

	memset(&buffer, 0, sizeof(buffer));

	responseMsg = buffer;

	int index = 0;

	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_RESPONSE:
			
		index = CheckForHook();

		if (index)
		{
			DbgPrint("ANTICHEAT: Hook Found in Disk Driver major function.");
			RtlStringCbPrintfA(buffer, sizeof(buffer), "ANTICHEAT: Hook Found in Disk Driver major function.");

			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			RtlCopyMemory(pBuf, buffer, strlen(buffer));
		}
		else
		{
			DbgPrint("ANTICHEAT: No Hook Found in Disk Driver major function.");
			RtlStringCbPrintfA(buffer, sizeof(buffer), "No Hook Found in Disk Driver major function.");

			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			RtlCopyMemory(pBuf, buffer, strlen(buffer));

			
		}

		

		break;

	default:
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(responseMsg);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT deviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT deviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return STATUS_SUCCESS;
}

const WCHAR deviceNameBuffer[] = L"\\Device\\ANTICHEATDEVICE";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\antiCheatDevice";

VOID OnUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

// register an event and wait for usermode to call us
void RegisterEvent(PDRIVER_OBJECT  DriverObject)
{
	NTSTATUS ntStatus = 0;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	// Normalize name and symbolic link.
	RtlInitUnicodeString(&deviceNameUnicodeString,
		deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString,
		deviceSymLinkBuffer);

	// Create the device.
	ntStatus = IoCreateDevice(DriverObject,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&myDevice);

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString,
		&deviceNameUnicodeString);

	DriverObject->DriverUnload = OnUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;
}

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,
	IN PUNICODE_STRING  RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS  status = 0;
		
	RegisterEvent(DriverObject);

	return status;
}