#pragma once

// Enable to add generic event data printing
#define INCLUDE_DUMP_EVENT (0)

#if INCLUDE_DUMP_EVENT

struct _EVENT_RECORD;
unsigned long DumpEvent(_EVENT_RECORD* pEvent);

#endif
