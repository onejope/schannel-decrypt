// dllmain.cpp : Defines the entry point for the DLL application.
#define SECURITY_WIN32 
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <ws2tcpip.h>
#include <security.h>
#include <schannel.h>
#include <iostream>
#include <fstream>

#include "detours.h"

#pragma comment (lib, "detours.lib")

FARPROC AddressOfDecryptMessage = 0;
// template for original function
typedef SECURITY_STATUS(__stdcall *OriginalDecryptMessage)(
    PCtxtHandle phContext,
    PSecBufferDesc pMessage,
    unsigned long MessageSeqNo,
    unsigned long *pfQOP
    );

SECURITY_STATUS __stdcall HookDecryptMessage(
        PCtxtHandle phContext,
        PSecBufferDesc pMessage,
        unsigned long MessageSeqNo,
        unsigned long* pfQOP) {
    std::cout << "DecryptMessage Hooked" << std::endl;

    OriginalDecryptMessage originalDecryptMessage = (OriginalDecryptMessage)AddressOfDecryptMessage;

    SECURITY_STATUS status = originalDecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);

    for (int i = 1; i < 4; i++) {
        if ((*pMessage).pBuffers[i].BufferType == SECBUFFER_DATA) {
            std::string receivedMessage((char*)(*pMessage).pBuffers[i].pvBuffer, (*pMessage).pBuffers[i].cbBuffer);
            std::cout << "From HookDecryptMessage: " << receivedMessage << std::endl;

            // This will log to decrypted_messages.txt in the current working directory of the process
            std::ofstream log_file("decrypted_messages.txt", std::ios_base::out | std::ios_base::app);
            log_file << "From HookDecryptMessage: " << receivedMessage << std::endl;
            break;
        }
    }

    return status;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HMODULE hSspicli;

    std::cout << "In DllMain" << std::endl;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hSspicli = GetModuleHandleA("SSPICLI");
        AddressOfDecryptMessage = GetProcAddress(hSspicli, "DecryptMessage");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // this will hook the function
        DetourAttach(&(LPVOID&)AddressOfDecryptMessage, &HookDecryptMessage);

        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        // unhook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(LPVOID&)AddressOfDecryptMessage, &HookDecryptMessage);

        DetourTransactionCommit();
        break;
    }
    return TRUE;
}

