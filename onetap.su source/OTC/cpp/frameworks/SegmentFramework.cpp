#include "../../framework.h"

void SegmentFramework::CreateInfoTable () {
    std::vector<DWORD> info;    
    info.emplace_back(reinterpret_cast<DWORD> (Utils::GetModule("steamclient.dll") + Links::LIBRARY));  
    for (const auto& library : m_libraries) info.emplace_back (reinterpret_cast<DWORD> (Utils::GetModule(library)));   
    Utils::FindOffsetsToVec (m_libraries.at(0), m_signatures, info, true);  
    std::memmove (reinterpret_cast<DWORD*> (Segment::GetSafeAllocationPointer () + 0x20), reinterpret_cast<PVOID> (info.data()), Links::TABLE); 
    std::memmove (reinterpret_cast<DWORD*> (Segment::GetSafeAllocationPointer () + 0x1), getenv ("USERNAME"), 0x20);    
}

void SegmentFramework::UpdateNetVars () {
    //Netvars are offsets to parent variables in valve sdk.
    for (const auto& netvar : m_netvars) {
        *reinterpret_cast<DWORD*> (Segment::GetSafeAllocationPointer () + netvar.rva) = netvar.new_value;
    }
}

void SegmentFramework::CreateHook () {                                                                                                                                                          //
      SetHook(reinterpret_cast<PVOID> (Segment::GetSafeAllocationPointer () + Links::HOOK), &CustomVirtualCaller, reinterpret_cast<PVOID*> (&OriginalVirtualFunctionCaller));         //
}

int SegmentFramework::CustomVirtualCaller (int* vTable, int index) {
	if (index >= 89) {
		index += 2;
		if (index >= 256) index++;
		if (index >= 300) index += 2;
		if (index >= 300) index++;
	}
	return SegmentFramework::OriginalVirtualFunctionCaller (vTable, index);
}