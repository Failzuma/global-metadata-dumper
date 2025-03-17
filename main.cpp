#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <format>

std::string WideCharToUtf8(const WCHAR* wstr)
{
	if (!wstr) return "";
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, nullptr, nullptr);
	if (!strTo.empty() && strTo.back() == '\0')
		strTo.pop_back();
	return strTo;
}

class HandleWrapper
{
public:
	explicit HandleWrapper(HANDLE handle) : h(handle)
	{
	}

	~HandleWrapper() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
	HandleWrapper(const HandleWrapper&) = delete;
	HandleWrapper& operator=(const HandleWrapper&) = delete;
	HANDLE get() const { return h; }

private:
	HANDLE h;
};

struct ProcessInfo
{
	std::string name;
	std::string path;
};

ProcessInfo get_process_info(DWORD pid)
{
	ProcessInfo info;
	HandleWrapper snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
	MODULEENTRY32 me{sizeof(me)};
	if (snapshot.get() != INVALID_HANDLE_VALUE && Module32First(snapshot.get(), &me))
	{
		info.name = WideCharToUtf8(me.szModule);
		info.path = WideCharToUtf8(me.szExePath);
	}
	else
	{
		info.name = "unknown";
		info.path = "";
	}
	return info;
}

DWORD get_process_id_by_name(const std::string& procName)
{
	DWORD pid = 0;
	HandleWrapper snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (snapshot.get() == INVALID_HANDLE_VALUE)
		return 0;
	PROCESSENTRY32 pe32{sizeof(PROCESSENTRY32)};
	if (Process32First(snapshot.get(), &pe32))
	{
		do
		{
			std::string exeName = WideCharToUtf8(pe32.szExeFile);
			if (procName == exeName)
			{
				pid = pe32.th32ProcessID;
				break;
			}
		}
		while (Process32Next(snapshot.get(), &pe32));
	}
	return pid;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::cerr << "Usage: dump.exe <ProcessName>\n";
		return 1;
	}
	std::string targetName = argv[1];
	DWORD pid = get_process_id_by_name(targetName);
	if (pid == 0)
	{
		std::cerr << std::format("[-] Process {} not found.\n", targetName);
		return 1;
	}
	std::cout << std::format("[*] Found process {} with PID: {}\n", targetName, pid);

	HandleWrapper process(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
	if (!process.get())
	{
		std::cerr << "[-] Failed to open process.\n";
		return 1;
	}
	auto procInfo = get_process_info(pid);
	std::cout << std::format("[*] Target process:\n    Name: {}\n    Path: {}\n", procInfo.name, procInfo.path);

	std::filesystem::path baseOutput = std::filesystem::current_path() / (procInfo.name + "_global-metadata.dat");
	std::cout << std::format("\n[*] Base output file: {}\n[*] Scanning memory for metadata pattern...\n",
	                         baseOutput.string());

	BYTE pattern[] = {0xAF, 0x1B, 0xB1, 0xFA};
	SIZE_T patternLen = sizeof(pattern);

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	auto addr = static_cast<LPBYTE>(sysInfo.lpMinimumApplicationAddress);
	auto maxAddr = static_cast<LPBYTE>(sysInfo.lpMaximumApplicationAddress);

	bool found = false;
	std::vector<BYTE> metadata;
	while (addr < maxAddr)
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(process.get(), addr, &mbi, sizeof(mbi)) == 0)
			break;
		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ)))
		{
			std::vector<BYTE> buffer(mbi.RegionSize);
			SIZE_T bytesRead = 0;
			if (ReadProcessMemory(process.get(), mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
			{
				for (SIZE_T i = 0; i <= bytesRead - patternLen; ++i)
				{
					if (memcmp(buffer.data() + i, pattern, patternLen) == 0)
					{
						LPBYTE matchAddr = static_cast<LPBYTE>(mbi.BaseAddress) + i;
						DWORD dataSize = 0, entryCount = 0;
						SIZE_T r = 0;
						LPBYTE sizeOffset = matchAddr + 0x100;
						LPBYTE countOffset = matchAddr + 0x104;
						if (!ReadProcessMemory(process.get(), sizeOffset, &dataSize, sizeof(DWORD), &r))
							continue;
						if (!ReadProcessMemory(process.get(), countOffset, &entryCount, sizeof(DWORD), &r))
							continue;
						if (entryCount < 10 || dataSize > 0x1000000)
						{
							sizeOffset = matchAddr + 0x108;
							countOffset = matchAddr + 0x10C;
							if (!ReadProcessMemory(process.get(), sizeOffset, &dataSize, sizeof(DWORD), &r))
								continue;
							if (!ReadProcessMemory(process.get(), countOffset, &entryCount, sizeof(DWORD), &r))
								continue;
						}
						DWORD totalSize = dataSize + entryCount;
						std::cout << std::format("[+] Calculated metadata size: {} bytes\n", totalSize);
						// idk why the fuck it sometimes return incorrect value
						// If totalSize is very small, assume it's incorrect and dump the entire region from matchAddr.
						if (totalSize < 0x1000)
							totalSize = static_cast<DWORD>(static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize -
								matchAddr);
						metadata.resize(totalSize);
						if (!ReadProcessMemory(process.get(), matchAddr, metadata.data(), totalSize, &r))
						{
							std::cout << "[-] Failed to read metadata from process memory.\n";
							continue;
						}
						DWORD origVersion = 0;
						memcpy(&origVersion, metadata.data() + 4, sizeof(DWORD));
						if (origVersion < 0x18 || origVersion > 0x1F)
						{
							std::cout << std::format("[-] Detected mangled metadata version: 0x{:X}\n", origVersion);
							for (DWORD candidate = 0x18; candidate <= 0x1F; candidate++)
							{
								std::vector<BYTE> candidateMetadata = metadata;
								memcpy(candidateMetadata.data() + 4, &candidate, sizeof(DWORD));
								std::filesystem::path candidateOutput = baseOutput;
								candidateOutput.replace_filename(
									std::format("{}_v{:X}_global-metadata.dat", procInfo.name, candidate));
								std::ofstream outfile(candidateOutput, std::ios::binary);
								if (!outfile)
								{
									std::cerr << std::format("[-] Failed to open candidate file: {}\n",
									                         candidateOutput.string());
									continue;
								}
								outfile.write(reinterpret_cast<const char*>(candidateMetadata.data()),
								              candidateMetadata.size());
								outfile.close();
								std::cout << std::format("[+] Dumped candidate metadata with version 0x{:X} to {}\n",
								                         candidate, candidateOutput.string());
							}
						}
						else
						{
							std::cout << std::format("[+] Metadata version: 0x{:X} ({:d})\n", origVersion, origVersion);
							std::ofstream outfile(baseOutput, std::ios::binary);
							if (!outfile)
								throw std::runtime_error("Failed to open output file");
							outfile.write(reinterpret_cast<const char*>(metadata.data()), metadata.size());
							outfile.close();
							std::cout << std::format("[+] Successfully dumped to {}\n", baseOutput.string());
						}
						found = true;
						break;
					}
				}
				if (found)
					break;
			}
		}
		addr = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
	}
	if (!found)
	{
		std::cout << "[-] Pattern not found.\n";
		return 1;
	}
	return 0;
}
