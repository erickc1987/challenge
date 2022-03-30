#include <windows.h>


#define SIOCTL_TYPE 40000

#define IOCTL_RESPONSE\
 CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


int main()
{
	HANDLE hDriver = CreateFile(L"\\\\.\\antiCheatDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesReturned = 0;

		char buffer[512];
		DeviceIoControl(hDriver, IOCTL_RESPONSE, NULL, 0, &buffer, sizeof(buffer), &dwBytesReturned, NULL);

		MessageBoxA(NULL, reinterpret_cast<LPCSTR>(buffer), "AntiCheat report", MB_OK);

		CloseHandle(hDriver);

	}
}