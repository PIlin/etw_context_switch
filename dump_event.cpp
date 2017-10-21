#include "dump_event.h"

#if INCLUDE_DUMP_EVENT

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <Evntrace.h>
#include <Evntcons.h>

#include <tdh.h>
#pragma comment(lib, "tdh.lib")
#include <wbemidl.h>
#include <wmistr.h>
#include <in6addr.h>

#include <cstdio>
#include <cstdlib>



//
// Based on https://msdn.microsoft.com/en-us/library/windows/desktop/ee441328(v=vs.85).aspx
//



DWORD GetEventInformation(PEVENT_RECORD pEvent, TRACE_EVENT_INFO*& pInfo)
{
	DWORD BufferSize = 0;

	// Retrieve the required buffer size for the event metadata.
	DWORD status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &BufferSize);

	if (ERROR_INSUFFICIENT_BUFFER == status)
	{
		pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
		if (pInfo == nullptr)
		{
			wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
			status = ERROR_OUTOFMEMORY;
			goto cleanup;
		}

		// Retrieve the event metadata.

		status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
	}

	if (ERROR_SUCCESS != status)
	{
		wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
	}

cleanup:

	return status;
}

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	// If the property is a binary blob and is defined in a manifest, the property can 
	// specify the blob's size or it can point to another property that defines the 
	// blob's size. The PropertyParamLength flag tells you where the blob's size is defined.

	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
	{
		DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
		DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
		*PropertyLength = (USHORT)Length;
	}
	else
	{
		if (pInfo->EventPropertyInfoArray[i].length > 0)
		{
			*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
		}
		else
		{
			// If the property is a binary blob and is defined in a MOF class, the extension
			// qualifier is used to determine the size of the blob. However, if the extension 
			// is IPAddrV6, you must set the PropertyLength variable yourself because the 
			// EVENT_PROPERTY_INFO.length field will be zero.

			if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
				TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
			{
				*PropertyLength = (USHORT)sizeof(IN6_ADDR);
			}
			else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				(pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
			{
				*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
			}
			else
			{
				wprintf(L"Unexpected length of 0 for intype %d and outtype %d\n",
					pInfo->EventPropertyInfoArray[i].nonStructType.InType,
					pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

				status = ERROR_EVT_INVALID_EVENT_DATA;
				goto cleanup;
			}
		}
	}

cleanup:

	return status;
}

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
	{
		DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
		DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
		*ArraySize = (USHORT)Count;
	}
	else
	{
		*ArraySize = pInfo->EventPropertyInfoArray[i].count;
	}

	return status;
}

// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
	DWORD ByteLength = 0;

	for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
	{
		ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
		*((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
	}
}

// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
	DWORD status = ERROR_SUCCESS;
	DWORD MapSize = 0;

	// Retrieve the required buffer size for the map info.

	status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

	if (ERROR_INSUFFICIENT_BUFFER == status)
	{
		pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
		if (pMapInfo == NULL)
		{
			wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
			status = ERROR_OUTOFMEMORY;
			goto cleanup;
		}

		// Retrieve the map info.

		status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
	}

	if (ERROR_SUCCESS == status)
	{
		if (DecodingSourceXMLFile == DecodingSource)
		{
			RemoveTrailingSpace(pMapInfo);
		}
	}
	else
	{
		if (ERROR_NOT_FOUND == status)
		{
			status = ERROR_SUCCESS; // This case is okay.
		}
		else
		{
			wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
		}
	}

cleanup:

	return status;
}


DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE& pUserData, PBYTE pEndOfUserData)
{
	TDHSTATUS status = ERROR_SUCCESS;
	USHORT PropertyLength = 0;
	DWORD FormattedDataSize = 0;
	USHORT UserDataConsumed = 0;
	USHORT UserDataLength = 0;
	LPWSTR pFormattedData = NULL;
	DWORD LastMember = 0;  // Last member of a structure
	USHORT ArraySize = 0;
	PEVENT_MAP_INFO pMapInfo = NULL;


	// Get the length of the property.

	status = GetPropertyLength(pEvent, pInfo, i, &PropertyLength);
	if (ERROR_SUCCESS != status)
	{
		wprintf(L"GetPropertyLength failed.\n");
		pUserData = NULL;
		goto cleanup;
	}

	// Get the size of the array if the property is an array.

	status = GetArraySize(pEvent, pInfo, i, &ArraySize);

	for (USHORT k = 0; k < ArraySize; k++)
	{
		// If the property is a structure, print the members of the structure.

		if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
		{
			LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
				pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

			for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
			{
				//pUserData = PrintProperties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData);
				status = PrintProperties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData);
				if (NULL == pUserData)
				{
					wprintf(L"Printing the members of the structure failed.\n");
					pUserData = NULL;
					goto cleanup;
				}
			}
		}
		else
		{
			// Get the name/value mapping if the property specifies a value map.

			status = GetMapInfo(pEvent,
				(PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
				pInfo->DecodingSource,
				pMapInfo);

			if (ERROR_SUCCESS != status)
			{
				wprintf(L"GetMapInfo failed\n");
				pUserData = NULL;
				goto cleanup;
			}

			// Get the size of the buffer required for the formatted data.

			status = TdhFormatProperty(
				pInfo,
				pMapInfo,
				PointerSize,
				pInfo->EventPropertyInfoArray[i].nonStructType.InType,
				pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
				PropertyLength,
				(USHORT)(pEndOfUserData - pUserData),
				pUserData,
				&FormattedDataSize,
				pFormattedData,
				&UserDataConsumed);

			if (ERROR_INSUFFICIENT_BUFFER == status)
			{
				if (pFormattedData)
				{
					free(pFormattedData);
					pFormattedData = NULL;
				}

				pFormattedData = (LPWSTR)malloc(FormattedDataSize);
				if (pFormattedData == NULL)
				{
					wprintf(L"Failed to allocate memory for formatted data (size=%lu).\n", FormattedDataSize);
					status = ERROR_OUTOFMEMORY;
					pUserData = NULL;
					goto cleanup;
				}

				// Retrieve the formatted data.

				status = TdhFormatProperty(
					pInfo,
					pMapInfo,
					PointerSize,
					pInfo->EventPropertyInfoArray[i].nonStructType.InType,
					pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
					PropertyLength,
					(USHORT)(pEndOfUserData - pUserData),
					pUserData,
					&FormattedDataSize,
					pFormattedData,
					&UserDataConsumed);
			}

			if (ERROR_SUCCESS == status)
			{
				wprintf(L"%s: %s\n",
					(PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset),
					pFormattedData);

				pUserData += UserDataConsumed;
			}
			else
			{
				wprintf(L"TdhFormatProperty failed with %lu.\n", status);
				pUserData = NULL;
				goto cleanup;
			}
		}
	}

cleanup:

	if (pFormattedData)
	{
		free(pFormattedData);
		pFormattedData = NULL;
	}

	if (pMapInfo)
	{
		free(pMapInfo);
		pMapInfo = NULL;
	}

	//return pUserData;
	return status;
}


DWORD DumpEvent(_EVENT_RECORD* pEvent)
{
	DWORD status = ERROR_SUCCESS;
	TRACE_EVENT_INFO* pInfo = NULL;
	LPWSTR pwsEventGuid = NULL;
	PBYTE pUserData = NULL;
	PBYTE pEndOfUserData = NULL;
	DWORD PointerSize = 0;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	SYSTEMTIME st;
	SYSTEMTIME stLocal;
	FILETIME ft;
	
	// Process the event. The pEvent->UserData member is a pointer to 
	// the event specific data, if it exists.

	status = GetEventInformation(pEvent, pInfo);

	if (ERROR_SUCCESS != status)
	{
		wprintf(L"GetEventInformation failed with %lu\n", status);
		goto cleanup;
	}

	// Determine whether the event is defined by a MOF class, in an
	// instrumentation manifest, or a WPP template; to use TDH to decode
	// the event, it must be defined by one of these three sources.

	if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
	{
		HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

		if (FAILED(hr))
		{
			wprintf(L"StringFromCLSID failed with 0x%x\n", hr);
			status = hr;
			goto cleanup;
		}

		wprintf(L"\nEvent GUID: %s\n", pwsEventGuid);
		CoTaskMemFree(pwsEventGuid);
		pwsEventGuid = NULL;

		wprintf(L"Event version: %d\n", pEvent->EventHeader.EventDescriptor.Version);
		wprintf(L"Event type: %d\n", pEvent->EventHeader.EventDescriptor.Opcode);
	}
	else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
	{
		wprintf(L"Event ID: %d\n", pInfo->EventDescriptor.Id);
	}
	else // Not handling the WPP case
	{
		goto cleanup;
	}

	if (pInfo->ProviderNameOffset)
	{
		wprintf(L"Event Provider: %s\n", (LPWSTR)((char*)pInfo + pInfo->ProviderNameOffset));
	}
	if (pInfo->TaskNameOffset)
	{
		wprintf(L"Event Task: %s\n", (LPWSTR)((char*)pInfo + pInfo->TaskNameOffset));
	}
	if (pInfo->OpcodeNameOffset)
	{
		wprintf(L"Event Opcode: %s\n", (LPWSTR)((char*)pInfo + pInfo->OpcodeNameOffset));
	}

	// Print the time stamp for when the event occurred.

	ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
	ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

	FileTimeToSystemTime(&ft, &st);
	SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

	TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
	Nanoseconds = (TimeStamp % 10000000) * 100;

	wprintf(L"%02d/%02d/%02d %02d:%02d:%02d.%I64u\n",
		stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);

	// If the event contains event-specific data use TDH to extract
	// the event data. For this example, to extract the data, the event 
	// must be defined by a MOF class or an instrumentation manifest.

	// Need to get the PointerSize for each event to cover the case where you are
	// consuming events from multiple log files that could have been generated on 
	// different architectures. Otherwise, you could have accessed the pointer
	// size when you opened the trace above (see pHeader->PointerSize).

	if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
	{
		PointerSize = 4;
	}
	else
	{
		PointerSize = 8;
	}
	
	pUserData = (PBYTE)pEvent->UserData;
	pEndOfUserData = (PBYTE)pEvent->UserData + pEvent->UserDataLength;

	// Print the event data for all the top-level properties. Metadata for all the 
	// top-level properties come before structure member properties in the 
	// property information array.

	for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
	{
		status = PrintProperties(pEvent, pInfo, PointerSize, i, pUserData, pEndOfUserData);
		if (NULL == pUserData || status != ERROR_SUCCESS)
		{
			wprintf(L"Printing top level properties failed.\n");
			goto cleanup;
		}
	}

cleanup:

	if (pInfo)
	{
		free(pInfo);
	}

	return status;
}


#endif // INCLUDE_DUMP_EVENT
