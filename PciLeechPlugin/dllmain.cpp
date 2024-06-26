#include "vmmdll.h"
#include <ReClassNET_Plugin.hpp>

#include <algorithm>
#include <cstdint>
#include <ios>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <format>

static uint64_t cbSize = 0x80000;
//callback for VfsFileListU
static VOID cbAddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
	if (strcmp(uszName, "dtb.txt") == 0)
		cbSize = cb;
}

struct Info
{
	uint32_t index;
	uint32_t process_id;
	uint64_t dtb;
	uint64_t kernelAddr;
	std::string name;
};

static VMM_HANDLE hVMM = 0;

bool FixCr3(VMM_HANDLE hVMM, DWORD dwPID, std::string uszModuleName)
{
	PVMMDLL_MAP_MODULEENTRY module_entry;
	bool result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, (LPSTR)uszModuleName.c_str(), &module_entry, NULL);
	if (result)
		return true; //Doesn't need to be patched lol

	if (!VMMDLL_InitializePlugins(hVMM))
	{
		return false;
	}

	//have to sleep a little or we try reading the file before the plugin initializes fully
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	while (true)
	{
		BYTE bytes[4] = { 0 };
		DWORD i = 0;
		auto nt = VMMDLL_VfsReadW(hVMM, (LPWSTR)L"\\misc\\procinfo\\progress_percent.txt", bytes, 3, &i, 0);
		if (nt == VMMDLL_STATUS_SUCCESS && atoi((LPSTR)bytes) == 100)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	VMMDLL_VFS_FILELIST2 VfsFileList;
	VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
	VfsFileList.h = 0;
	VfsFileList.pfnAddDirectory = 0;
	VfsFileList.pfnAddFile = cbAddFile;

	result = VMMDLL_VfsListU(hVMM, (LPSTR)"\\misc\\procinfo\\", &VfsFileList);
	if (!result)
		return false;

	//read the data from the txt and parse it
	const size_t buffer_size = cbSize;
	std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
	DWORD j = 0;
	auto nt = VMMDLL_VfsReadW(hVMM, (LPWSTR)L"\\misc\\procinfo\\dtb.txt", bytes.get(), buffer_size - 1, &j, 0);
	if (nt != VMMDLL_STATUS_SUCCESS)
		return false;

	std::vector<uint64_t> possible_dtbs;
	std::string lines(reinterpret_cast<char*>(bytes.get()));
	std::istringstream iss(lines);
	std::string line;

	while (std::getline(iss, line))
	{
		Info info = { };

		std::istringstream info_ss(line);
		if (info_ss >> std::hex >> info.index >> std::dec >> info.process_id >> std::hex >> info.dtb >> info.kernelAddr >> info.name)
		{
			if (info.process_id == 0) //parts that lack a name or have a NULL pid are suspects
				possible_dtbs.push_back(info.dtb);
			if (uszModuleName.find(info.name) != std::string::npos)
				possible_dtbs.push_back(info.dtb);
		}
	}

	//loop over possible dtbs and set the config to use it til we find the correct one
	for (size_t i = 0; i < possible_dtbs.size(); i++)
	{
		auto dtb = possible_dtbs[i];
		VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_PROCESS_DTB | dwPID, dtb);
		result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, (LPSTR)uszModuleName.c_str(), &module_entry, NULL);
		auto base = VMMDLL_ProcessGetModuleBaseU(hVMM, dwPID, (LPSTR)uszModuleName.c_str());
		if (result)
		{
			return true;
		}
	}

	return false;
}

extern "C" void RC_CallConv EnumerateProcesses(EnumerateProcessCallback callbackProcess) {
	if (callbackProcess == nullptr) {
		return;
	}

	// TODO: Ghetto init code, make this better
	static bool init = false;

	if (!init) {
		LPCSTR argv[] =
		{
		(""),
		("-device"),
		("fpga"),
		("-norefresh"),
		("-pagefile0"),
		("pagefile.sys"),
		("-pagefile1"),
		("swapfile.sys"),
		("-memmap"),
		("mmap.txt")
		};
		hVMM = VMMDLL_Initialize(3, argv);

		if (!hVMM) {
			MessageBoxA(0, "FAIL: VMMDLL_Initialize", 0, MB_OK | MB_ICONERROR);

			ExitProcess(-1);
		}

		init = true;
	}

	BOOL result;
	ULONG64 cPIDs = 0;
	DWORD i, * pPIDs = NULL;

	result = VMMDLL_PidList(hVMM, NULL, &cPIDs) && (pPIDs = (DWORD*)LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD))) && VMMDLL_PidList(hVMM, pPIDs, &cPIDs);

	if (!result) {
		VMMDLL_MemFree(pPIDs);
		return;
	}

	for (i = 0; i < cPIDs; i++) {
		DWORD dwPID = pPIDs[i];

		VMMDLL_PROCESS_INFORMATION info;
		SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
		ZeroMemory(&info, cbInfo);
		info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
		info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

		result = VMMDLL_ProcessGetInformation(hVMM, dwPID, &info, &cbInfo);

		if (result) {
			EnumerateProcessData data = {};
			data.Id = dwPID;
			MultiByteToUnicode(info.szNameLong, data.Name, PATH_MAXIMUM_LENGTH);

			LPSTR szPathUser = VMMDLL_ProcessGetInformationString(hVMM, dwPID, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);

			if (szPathUser) {
				MultiByteToUnicode(szPathUser, data.Path, PATH_MAXIMUM_LENGTH);
			}

			callbackProcess(&data);
		}
	}

	VMMDLL_MemFree(pPIDs);
}

extern "C" void RC_CallConv EnumerateRemoteSectionsAndModules(
	RC_Pointer handle,
	EnumerateRemoteSectionsCallback callbackSection,
	EnumerateRemoteModulesCallback callbackModule) {
	if (callbackSection == nullptr && callbackModule == nullptr) {
		return;
	}

	BOOL result;
	DWORD dwPID = (DWORD)handle;
	ULONG64 i, j;

	PVMMDLL_MAP_PTE pMemMapEntries = NULL;
	PVMMDLL_MAP_PTEENTRY memMapEntry = NULL;

	result = VMMDLL_Map_GetPte(hVMM, dwPID, TRUE, &pMemMapEntries);

	if (!result) {
		MessageBoxA(0, "FAIL: VMMDLL_Map_GetPte", 0, MB_OK | MB_ICONERROR);

		ExitProcess(-1);
	}

	if (!result) {
		VMMDLL_MemFree(pMemMapEntries);

		return;
	}

	SIZE_T cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
	VMMDLL_PROCESS_INFORMATION GameInfo;
	ZeroMemory(&GameInfo, sizeof(VMMDLL_PROCESS_INFORMATION));
	GameInfo.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
	GameInfo.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
	if (!VMMDLL_ProcessGetInformation(hVMM, dwPID, &GameInfo, &cbProcessInformation))
	{
		MessageBoxA(0, "FAIL: VMMDLL_ProcessGetInformation", 0, MB_OK | MB_ICONERROR);
		return;
	}

	if (!FixCr3(hVMM, dwPID, GameInfo.szName))
	{
		MessageBoxA(0, std::format("FAIL: FixCr3 :{}", GameInfo.szName).c_str(), 0, MB_OK | MB_ICONERROR);
		return;
	}

	std::vector< EnumerateRemoteSectionData > sections;

	for (i = 0; i < pMemMapEntries->cMap; i++) {
		memMapEntry = &pMemMapEntries->pMap[i];

		EnumerateRemoteSectionData section = {};
		section.BaseAddress = (RC_Pointer)memMapEntry->vaBase;
		section.Size = memMapEntry->cPages << 12;

		section.Protection = SectionProtection::NoAccess;
		section.Category = SectionCategory::Unknown;

		if (memMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS)
			section.Protection |= SectionProtection::Read;
		if (memMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W)
			section.Protection |= SectionProtection::Write;
		if (!(memMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX))
			section.Protection |= SectionProtection::Execute;

		if (memMapEntry->wszText[0]) {
			if ((memMapEntry->wszText[0] == 'H' && memMapEntry->wszText[1] == 'E' && memMapEntry->wszText[2] == 'A' &&
				memMapEntry->wszText[3] == 'P') ||
				(memMapEntry->wszText[0] == '[' && memMapEntry->wszText[1] == 'H' && memMapEntry->wszText[2] == 'E' &&
					memMapEntry->wszText[3] == 'A' && memMapEntry->wszText[4] == 'P')) {
				section.Type = SectionType::Private;

			}
			else {
				section.Type = SectionType::Image;


				LPWSTR w = memMapEntry->wszText;
				char c[64] = { 0 };
				wcstombs(c, w, wcslen(w));

				MultiByteToUnicode(c, section.ModulePath, PATH_MAXIMUM_LENGTH);

			}
		}
		else {
			section.Type = SectionType::Mapped;
		}

		sections.push_back(std::move(section));
	}
	VMMDLL_MemFree(pMemMapEntries);

	PVMMDLL_MAP_MODULE pModuleEntries = NULL;
	result = VMMDLL_Map_GetModule(hVMM, dwPID, &pModuleEntries, VMMDLL_MODULE_FLAG_NORMAL);

	if (!result) {
		MessageBoxA(0, "FAIL: VMMDLL_Map_GetModule", 0, MB_OK | MB_ICONERROR);

		ExitProcess(-1);
	}

	if (!result) {
		VMMDLL_MemFree(pModuleEntries);

		return;
	}

	for (i = 0; i < pModuleEntries->cMap; i++) {

		EnumerateRemoteModuleData data = {};
		data.BaseAddress = (RC_Pointer)pModuleEntries->pMap[i].vaBase;
		data.Size = (RC_Size)pModuleEntries->pMap[i].cbImageSize;


		LPWSTR ws = pModuleEntries->pMap[i].wszText;
		char cs[64] = { 0 };
		wcstombs(cs, ws, wcslen(ws));


		MultiByteToUnicode(cs, data.Path, PATH_MAXIMUM_LENGTH);

		callbackModule(&data);

		// !!!!!!!!!
		// <warning>
		// this code crashes some processes, possibly a bug with vmm.dll
		DWORD cSections = 0;
		PIMAGE_SECTION_HEADER sectionEntry, pSections = NULL;

		result = VMMDLL_ProcessGetSections(hVMM, dwPID, pModuleEntries->pMap[i].wszText, NULL, 0, &cSections) && cSections &&
			(pSections = (PIMAGE_SECTION_HEADER)LocalAlloc(0, cSections * sizeof(IMAGE_SECTION_HEADER))) &&
			VMMDLL_ProcessGetSections(hVMM, dwPID, pModuleEntries->pMap[i].wszText, pSections, cSections, &cSections);

		if (result) {
			for (j = 0; j < cSections; j++) {
				sectionEntry = pSections + j;

				auto it =
					std::lower_bound(std::begin(sections), std::end(sections), reinterpret_cast<LPVOID>(pModuleEntries->pMap[i].vaBase),
						[&sections](const auto& lhs, const LPVOID& rhs) { return lhs.BaseAddress < rhs; });

				auto sectionAddress = (uintptr_t)(pModuleEntries->pMap[i].vaBase + sectionEntry->VirtualAddress);

				for (auto k = it; k != std::end(sections); ++k) {
					uintptr_t start = (uintptr_t)k->BaseAddress;
					uintptr_t end = (uintptr_t)k->BaseAddress + k->Size;

					if (sectionAddress >= start && sectionAddress < end) {
						// Copy the name because it is not null padded.
						char buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
						std::memcpy(buffer, sectionEntry->Name, IMAGE_SIZEOF_SHORT_NAME);

						if (std::strcmp(buffer, ".text") == 0 || std::strcmp(buffer, "code") == 0) {
							k->Category = SectionCategory::CODE;
						}
						else if (std::strcmp(buffer, ".data") == 0 || std::strcmp(buffer, "data") == 0 ||
							std::strcmp(buffer, ".rdata") == 0 || std::strcmp(buffer, ".idata") == 0) {
							k->Category = SectionCategory::DATA;
						}
						MultiByteToUnicode(buffer, k->Name, IMAGE_SIZEOF_SHORT_NAME);
					}
				}
			}
		}
		VMMDLL_MemFree(pSections);
		// </warning>
		// !!!!!!!!!!
	}
	//	VMMDLL_MemFree( pSections );
		// </warning>
		// !!!!!!!!!!


	if (callbackSection != nullptr) {
		for (auto&& section : sections) {
			callbackSection(&section);
		}
	}
}

extern "C" RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess desiredAccess) {
	return id;
}

extern "C" bool RC_CallConv IsProcessValid(RC_Pointer handle) {
	VMMDLL_PROCESS_INFORMATION info;
	SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
	ZeroMemory(&info, cbInfo);
	info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
	info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

	if (VMMDLL_ProcessGetInformation(hVMM, (DWORD)handle, &info, &cbInfo)) {
		return true;
	}

	return false;
}

extern "C" void RC_CallConv CloseRemoteProcess(RC_Pointer handle) {
}

extern "C" bool RC_CallConv ReadRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size) {
	buffer = reinterpret_cast<RC_Pointer>(reinterpret_cast<uintptr_t>(buffer) + offset);

	if (VMMDLL_MemReadEx(hVMM, (DWORD)handle, (ULONG64)address, (PBYTE)buffer, size, NULL, VMMDLL_FLAG_NOCACHE)) {
		return true;
	}

	return false;
}

extern "C" bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size) {
	buffer = reinterpret_cast<RC_Pointer>(reinterpret_cast<uintptr_t>(buffer) + offset);

	if (VMMDLL_MemWrite(hVMM, (DWORD)handle, (ULONG64)address, (PBYTE)buffer, size)) {
		return true;
	}

	return false;
}

////////////////////////////////////////
////////////////////////////////////////
// Remote debugging is not supported
////////////////////////////////////////
////////////////////////////////////////

extern "C" void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action) {
}

extern "C" bool RC_CallConv AttachDebuggerToProcess(RC_Pointer id) {
	return false;
}

extern "C" void RC_CallConv DetachDebuggerFromProcess(RC_Pointer id) {
}

extern "C" bool RC_CallConv AwaitDebugEvent(DebugEvent* evt, int timeoutInMilliseconds) {
	return false;
}

extern "C" void RC_CallConv HandleDebugEvent(DebugEvent* evt) {
}

extern "C" bool RC_CallConv SetHardwareBreakpoint(RC_Pointer id, RC_Pointer address, HardwareBreakpointRegister reg, HardwareBreakpointTrigger type,
	HardwareBreakpointSize size, bool set) {
	return false;
}
