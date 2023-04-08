#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

void error(const char* message)
{
    printf("[error] %s\n", message);
    while (true) {}
    exit(0);
}

bool dump_file(BYTE* payload, uint32_t size, std::string name)
{
    std::string path = (std::filesystem::current_path() / name).string();

    std::ofstream file_ofstream(path, std::ios_base::out | std::ios_base::binary);

    if (!file_ofstream.write((const char*)payload, size)) {
        file_ofstream.close();
        return false;
    }

    file_ofstream.close();
    return true;
}

int main()
{
    int pid;
    uint64_t address;

    std::cout << "Enter pid: ";
    std::cin >> pid;
    std::cout << std::endl;

    std::cout << "Enter address: 0x";
    std::cin >> std::hex >> address;
    std::cout << std::endl;

    std::cout << "Dumping 0x" << std::hex << std::uppercase << address;
    std::cout << std::endl;

    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    _IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(hprocess, (void*)address, &dos, sizeof(dos), 0))
        error("Cannot read DOS header");

    _IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(hprocess, (void*)(address + dos.e_lfanew), &nt, sizeof(nt), 0))
        error("Cannot read NT headers");

    if (nt.Signature != IMAGE_NT_SIGNATURE)
        error("File is not a valid PE file");

    const auto size = nt.OptionalHeader.SizeOfImage;

    BYTE* payload = new BYTE[size];
    ReadProcessMemory(hprocess, (void*)address, &(*payload), size, 0);

    std::stringstream stream;
    stream << std::hex << std::uppercase << address;
    stream << "_dump.bin";

    dump_file(payload, size, stream.str());

    std::stringstream stream2;
    stream2 << std::hex << std::uppercase << address;
    stream2 << "_hex_dump.text";

    std::stringstream stream3;

    std::ofstream byte_dump(stream2.str());
    stream3 << "// 0x" << std::uppercase << std::hex << address << std::endl;
    stream3 << "BYTE shell_code[" << std::uppercase << std::hex << size << "] = {" << std::endl;
    for (int i = 0; i < size; i++) {
        char buf[6];
        sprintf_s(buf, "0x%X", payload[i]);

        stream3 << buf << ",";
    }
    stream3 << "};";

    byte_dump.write(stream3.str().data(), stream3.str().size());
    byte_dump.close();

    CloseHandle(hprocess);
    printf("Dumped: %s\n", stream2.str().c_str());
    
    Sleep(5000);
    ExitProcess(0);
}
