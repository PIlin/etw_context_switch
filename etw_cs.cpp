#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define INITGUID  // Causes definition of SystemTraceControlGuid in evntrace.h. Has to be done once per executable/library.
#include <Evntrace.h>
#include <Evntcons.h>

#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <thread>

#include "dump_event.h"


//#define LIMIT_EVENTS_COUNT (10000)



void PrintSystemError(DWORD err)
{
	char buf[1024];
	DWORD bufSize = sizeof(buf);
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, err, LANG_NEUTRAL, buf, bufSize, nullptr);

	::fprintf(stderr, "error %u: %s\n", err, buf);
}


struct SPropertiesDeleter
{
	void operator()(EVENT_TRACE_PROPERTIES* p)
	{
		::free(p);
	}
};

using EventTracePropertiesPtr = std::unique_ptr<EVENT_TRACE_PROPERTIES, SPropertiesDeleter>;

EventTracePropertiesPtr AllocSessionProperties()
{
	const size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
	EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)::malloc(bufferSize);
	::memset(pSessionProperties, 0, bufferSize);

	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_CSWITCH;
	pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	pSessionProperties->Wnode.BufferSize = bufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1; // timestamp from QueryPerformanceCounter
	pSessionProperties->Wnode.Guid = SystemTraceControlGuid;

	::memcpy((char*)pSessionProperties + pSessionProperties->LoggerNameOffset, KERNEL_LOGGER_NAME, sizeof(KERNEL_LOGGER_NAME));

	return EventTracePropertiesPtr(pSessionProperties);
}

bool StartTraceSession(TRACEHANDLE& outSessionHandle)
{
	EventTracePropertiesPtr pSessionProperties = AllocSessionProperties();

	const ULONG status = StartTrace(&outSessionHandle, KERNEL_LOGGER_NAME, pSessionProperties.get());
	if (status != ERROR_SUCCESS)
	{
		PrintSystemError(status);
		return false;
	}
	return true;
}

bool StopTraceSession()
{
	EventTracePropertiesPtr pSessionProperties = AllocSessionProperties();

	const ULONG status = ControlTrace(NULL, KERNEL_LOGGER_NAME, pSessionProperties.get(), EVENT_TRACE_CONTROL_STOP);
	if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND)
	{
		PrintSystemError(status);
		return false;
	}
	return true;
}


// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa964744(v=vs.85).aspx
struct CSwitch_Event
{
	using uint32 = uint32_t;
	using sint8 = int8_t;
	using uint8 = uint8_t;
	enum { EventVersion = 3 };
	enum { EventOpcode = 36 };

	uint32 NewThreadId;
	uint32 OldThreadId;
	sint8  NewThreadPriority;
	sint8  OldThreadPriority;
	uint8  PreviousCState;
	sint8  SpareByte;
	sint8  OldThreadWaitReason;
	sint8  OldThreadWaitMode;
	sint8  OldThreadState;
	sint8  OldThreadWaitIdealProcessor;
	uint32 NewThreadWaitTime;
	uint32 Reserved;

	void Print() const
	{
		::printf("NewThreadId = 0x%x\n", NewThreadId);
		::printf("OldThreadId = 0x%x\n", OldThreadId);
		::printf("NewThreadPriority = %d\n", NewThreadPriority);
		::printf("OldThreadPriority = %d\n", OldThreadPriority);
		::printf("PreviousCState = %u\n", PreviousCState);
		::printf("OldThreadWaitReason = %d %s\n", OldThreadWaitReason, GetWaitReasonName(OldThreadWaitReason));
		::printf("OldThreadWaitMode = %d %s\n", OldThreadWaitMode, GetWaitModeName(OldThreadWaitMode));
		::printf("OldThreadState = %d %s\n", OldThreadState, GetStateName(OldThreadState));
		::printf("OldThreadWaitIdealProcessor = %d\n", OldThreadWaitIdealProcessor);
		::printf("NewThreadWaitTime = %u\n", NewThreadWaitTime);
	}

	static const char* GetStateName(int state)
	{
		switch (state)
		{
		case 0: return "Initialized";
		case 1: return "Ready";
		case 2: return "Running";
		case 3: return "Standby";
		case 4: return "Terminated";
		case 5: return "Waiting";
		case 6: return "Transition";
		case 7: return "DeferredReady";
		}
		return "<UnknownValue>";
	}

	static const char* GetWaitModeName(int mode)
	{
		switch (mode)
		{
		case 0: return "KernelMode";
		case 1: return "UserMode";
		}
		return "<UnknownValue>";
	}

	static const char* GetWaitReasonName(int reason)
	{
		switch (reason)
		{
		case 0: return "Executive";
		case 1: return "FreePage";
		case 2: return "PageIn";
		case 3: return "PoolAllocation";
		case 4: return "DelayExecution";
		case 5: return "Suspended";
		case 6: return "UserRequest";
		case 7: return "WrExecutive";
		case 8: return "WrFreePage";
		case 9: return "WrPageIn";
		case 10: return "WrPoolAllocation";
		case 11: return "WrDelayExecution";
		case 12: return "WrSuspended";
		case 13: return "WrUserRequest";
		case 14: return "WrEventPair";
		case 15: return "WrQueue";
		case 16: return "WrLpcReceive";
		case 17: return "WrLpcReply";
		case 18: return "WrVirtualMemory";
		case 19: return "WrPageOut";
		case 20: return "WrRendezvous";
		case 21: return "WrKeyedEvent";
		case 22: return "WrTerminated";
		case 23: return "WrProcessInSwap";
		case 24: return "WrCpuRateControl";
		case 25: return "WrCalloutStack";
		case 26: return "WrKernel";
		case 27: return "WrResource";
		case 28: return "WrPushLock";
		case 29: return "WrMutex";
		case 30: return "WrQuantumEnd";
		case 31: return "WrDispatchInt";
		case 32: return "WrPreempted";
		case 33: return "WrYieldExecution";
		case 34: return "WrFastMutex";
		case 35: return "WrGuardedMutex";
		case 36: return "WrRundown";
		case 37: return "MaximumWaitReason";
		}
		return "<UnknownValue>";
	}
};
static_assert(sizeof(CSwitch_Event) == 24, "unexpected size of CSwitch_Event");


static void DumpBasicEventData(EVENT_RECORD* pEvent)
{
	const EVENT_HEADER& h = pEvent->EventHeader;
	printf("size %u, type %u, flags %x, proc %u, tid %u, pid %u, ts %llu, id %u, ver %u, ch %u, lv %u, op %u, task %u, kw %llu\n"
		, h.Size
		, h.HeaderType
		, h.Flags
		, pEvent->BufferContext.ProcessorIndex
		, h.ThreadId
		, h.ProcessId
		, h.TimeStamp.QuadPart
		, h.EventDescriptor.Id
		, h.EventDescriptor.Version
		, h.EventDescriptor.Channel
		, h.EventDescriptor.Level
		, h.EventDescriptor.Opcode
		, h.EventDescriptor.Task
		, h.EventDescriptor.Keyword
	);
}


class STraceLogProcessor
{
public:
	static void RunBlocking()
	{
		assert(g_consumerHandle == INVALID_PROCESSTRACE_HANDLE);
		
		TRACEHANDLE consumerHandle;
		if (OpenTraceForProcessing(consumerHandle))
		{
			g_consumerHandle = consumerHandle;

			std::thread t([](TRACEHANDLE consumerHandle)
			{
				DWORD status = ProcessTrace(&consumerHandle, 1, 0, 0);
				PrintSystemError(status);
			}, consumerHandle);

			// TODO: don't join thread here to perform non-blocking processing
			// Call StopTraceProcessing() to stop processing thread
			t.join();

			::printf("eventsCount = %d\n", g_eventsCount);

			StopTraceProcessing();
		}
	}

private:

	static bool OpenTraceForProcessing(TRACEHANDLE& outConsumerHandle)
	{
		EVENT_TRACE_LOGFILE logFile = { 0 };
		logFile.LoggerName = KERNEL_LOGGER_NAME;
		logFile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME |
			PROCESS_TRACE_MODE_EVENT_RECORD |
			PROCESS_TRACE_MODE_RAW_TIMESTAMP);
		logFile.EventRecordCallback = &ProcessEventRecordCallback;

		outConsumerHandle = OpenTrace(&logFile);
		if (outConsumerHandle == INVALID_PROCESSTRACE_HANDLE)
		{
			PrintSystemError(GetLastError());
			return false;
		}
		return true;
	}

	static void StopTraceProcessing()
	{
		if (g_consumerHandle != INVALID_PROCESSTRACE_HANDLE)
		{
			DWORD status = CloseTrace(g_consumerHandle);
			if (status != ERROR_SUCCESS || status != ERROR_CTX_CLOSE_PENDING)
			{
				PrintSystemError(status);
			}
			g_consumerHandle = INVALID_PROCESSTRACE_HANDLE;
		}
	}


	static void WINAPI ProcessEventRecordCallback(EVENT_RECORD* pEvent)
	{
		DWORD status = ERROR_SUCCESS;

		const EVENT_HEADER& h = pEvent->EventHeader;

		if (h.EventDescriptor.Version == CSwitch_Event::EventVersion && h.EventDescriptor.Opcode == CSwitch_Event::EventOpcode)
		{
			if (pEvent->UserDataLength == sizeof(CSwitch_Event))
			{
				const CSwitch_Event* pCSwitch = reinterpret_cast<const CSwitch_Event*>(pEvent->UserData);
				DumpBasicEventData(pEvent);
				pCSwitch->Print();
			}
			else
			{
				// shouldn't happen
				status = ERROR_INVALID_PARAMETER;
			}
		}
		else
		{
#if INCLUDE_DUMP_EVENT
			// Skips the event if it is the event trace header. Log files contain this event
			// but real-time sessions do not. The event contains the same information as 
			// the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
			// the trace. 

			//if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
			//	h.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
			//{
			//	status = ERROR_SUCCESS;
			//	; // Skip this event.
			//}
			//else
			//{
			//	DumpBasicEventData(pEvent);
			//	status = DumpEvent(pEvent);
			//}
#endif
		}

		g_eventsCount++;
		//::printf("ev %d\n", g_eventsCount);

		if (ERROR_SUCCESS != status 
#if defined(LIMIT_EVENTS_COUNT)
			|| g_eventsCount == LIMIT_EVENTS_COUNT
#endif
			)
		{
			StopTraceProcessing();
		}
	}


private:
	static TRACEHANDLE g_consumerHandle;
	static int g_eventsCount;
};
/*static*/ TRACEHANDLE STraceLogProcessor::g_consumerHandle = INVALID_PROCESSTRACE_HANDLE;
/*static*/ int STraceLogProcessor::g_eventsCount = 0;



int main()
{
	if (!StopTraceSession())
		return 1;
	
	TRACEHANDLE sessionHandle;
	if (!StartTraceSession(sessionHandle))
		return 1;

	STraceLogProcessor::RunBlocking();

	StopTraceSession();

    return 0;
}

