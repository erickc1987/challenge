#include <ntddk.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <intrin.h>
#include <ntstrsafe.h>

PDEVICE_OBJECT myDevice;
PDRIVER_DISPATCH originalDeviceControl;

#define SIOCTL_TYPE 40000

#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_HIDE\
 CTL_CODE( SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

PDRIVER_OBJECT ourDriverObject = NULL;

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

NTSTATUS hookedDeviceControl(PDEVICE_OBJECT device_object, PIRP irp)
{
	return originalDeviceControl(device_object, irp);
}

void HideHooks(void)
{
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
		return;
	}

	// replace all irps with our own

	memcpy(driverObject->MajorFunction, ourDriverObject->MajorFunction, IRP_MJ_MAXIMUM_FUNCTION + 1);

	// okay all entries are hooked, but we can still see that the entries are outside the device
	// quick and dirty hack to replace the kldr entry with our cheat driver

	driverObject->DriverSection = ourDriverObject->DriverSection;

	// this only allows us to fool range checks and isn't a very clever bypass
}

int HookEntry(void)
{
	static int hooked = 0;

	if (!hooked)
	{

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
			return hooked;
		}

		// hook the major function for DeviceIOControl

		originalDeviceControl = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &hookedDeviceControl;

		ObDereferenceObject(driverObject);

		hooked = 1;
	}

	return hooked;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT deviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(deviceObject);

	PIO_STACK_LOCATION pIoStackLocation;
	PCHAR responseMsg = NULL;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	int hooked = 0;

	char buffer[256];

	memset(&buffer, 0, sizeof(buffer));

	responseMsg = buffer;

	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HELLO:
		DbgPrint("CHEAT: Response to Userland.");

		hooked = HookEntry();

		// hook an entry to redirect control to us to spoof or do whatever
		if (hooked)
		{
			RtlStringCbPrintfA(buffer, sizeof(buffer), "CHEAT: DeviceIOControl is already hooked for disk driver");

			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			RtlCopyMemory(pBuf, buffer, strlen(buffer));
		}
		else
		{
			RtlStringCbPrintfA(buffer, sizeof(buffer), "CHEAT: DeviceIOControl is hooked for disk driver");

			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			RtlCopyMemory(pBuf, buffer, strlen(buffer));
		}

		break;
	case IOCTL_HIDE:

		HideHooks();

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

const WCHAR deviceNameBuffer[] = L"\\Device\\CHEATDEVICE";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\cheatDevice";

VOID OnUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

// register and wait for usermode
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

	ourDriverObject = DriverObject;
		
	RegisterEvent(DriverObject);
    
    return status;
}