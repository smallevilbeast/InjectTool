// InjectTool.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "InjectTool.h"
#include <commdlg.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>

DWORD GetProcessId(LPSTR name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    BOOL bRet = Process32First(hSnapshot, &processEntry);
    DWORD dwProcessId = 0;
    while (bRet)
    {
        if (_tcscmp(processEntry.szExeFile, name) == 0) {
            dwProcessId = processEntry.th32ProcessID;
            break;
        }
        bRet = Process32Next(hSnapshot, &processEntry);
    }

    CloseHandle(hSnapshot);
    return dwProcessId;
}


BOOL UninjectDll(LPSTR szExeName, LPSTR szDllName)
{
    // 获取进程id
    DWORD dwProcessId = GetProcessId(szExeName);
    if (dwProcessId == 0) return FALSE;


    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(me32);

    //查找匹配的进程名称
    BOOL bRet = Module32First(hSnap, &me32);
    BOOL bFind = FALSE;
    while (bRet)
    {
        if (lstrcmp(me32.szExePath, szDllName) == 0)
        {   
            char  szBuffer[100];
            sprintf_s(szBuffer, 100, "%d", me32.hModule);
            bFind = TRUE;
            break;
        }
        bRet = Module32Next(hSnap, &me32);
    }
    
    CloseHandle(hSnap);
    if (!bFind) return FALSE;

    char *pFunName = "FreeLibrary";
  
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    if (hProcess == NULL)
    {
        return FALSE;
    }

    FARPROC pFunAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), pFunName);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunAddr, me32.hModule, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

BOOL InjectDll(LPSTR exeName, LPSTR dllName)
{

    // 获取进程id
    DWORD dwProcessId = GetProcessId(exeName);
    if (dwProcessId == 0) return FALSE;

    // 获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == INVALID_HANDLE_VALUE) return FALSE;

    // 在目标进程中申请内存
    DWORD dwDllNameLength = _tcslen(dllName) + 6;
    LPVOID lpAlloAddr = VirtualAllocEx(hProcess, NULL, dwDllNameLength, MEM_COMMIT, PAGE_READWRITE);
    if (lpAlloAddr == NULL)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 拷贝dll路径名字到目标进程的内存
    BOOL bWriteRet = WriteProcessMemory(hProcess, lpAlloAddr, (LPVOID)dllName, dwDllNameLength, NULL);
    if (!bWriteRet)
    {
        CloseHandle(hProcess);
        VirtualFreeEx(hProcess, lpAlloAddr, dwDllNameLength, MEM_RELEASE);
        return FALSE;
    }

    // 获取模块地址
    HMODULE hModule = GetModuleHandle(_T("Kernel32.dll"));
    if (!hModule)
    {
        CloseHandle(hProcess);
        VirtualFreeEx(hProcess, lpAlloAddr, dwDllNameLength, MEM_RELEASE);
        return FALSE;
    }

    // 获取LoadLibrary函数地址	
    DWORD dwLoadLibrary = (DWORD)GetProcAddress(hModule, _T("LoadLibraryA"));
    if (!dwLoadLibrary)
    {
        CloseHandle(hProcess);
        VirtualFreeEx(hProcess, lpAlloAddr, dwDllNameLength, MEM_RELEASE);
        FreeLibrary(hModule);
        return FALSE;
    }
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwLoadLibrary, lpAlloAddr, 0, NULL);
    WaitForSingleObject(hThread, 3000);
    BOOL bRet;
    if (hThread != INVALID_HANDLE_VALUE) {
        bRet = TRUE;
    }
    else {
        bRet = FALSE;
    }

    CloseHandle(hProcess);
    VirtualFreeEx(hProcess, lpAlloAddr, dwDllNameLength, MEM_RELEASE);
    FreeLibrary(hModule);
    CloseHandle(hThread);
    return bRet;
}



VOID OnOpenFileClicked(_In_ HWND   hwndDlg)
{
    OPENFILENAME ofn;
    TCHAR szFile[MAX_PATH];

    // Initialize OPENFILENAME
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwndDlg;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
    // use the contents of szFile to initialize itself.
    //
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = _T("DLL文件(*.dll)\0*.dll\0\0");
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrTitle = _T("打开");
    if (GetOpenFileName(&ofn))
    {
        SetDlgItemText(hwndDlg, EDIT_DLL_PATH, szFile);
    }
}
VOID OnBtnClicked(_In_ HWND   hwndDlg, _In_ WPARAM wParam)
{
    if (wParam == BTN_FILE)
    {
        OnOpenFileClicked(hwndDlg);
    } 
    else if (wParam == BTN_INJECT)
    {
        TCHAR szExeName[50];
        TCHAR szDllPath[MAX_PATH];

        GetDlgItemText(hwndDlg, EDIT_PROCESS_NAME, szExeName, sizeof(szExeName));
        GetDlgItemText(hwndDlg, EDIT_DLL_PATH, szDllPath, sizeof(szDllPath));
        if (InjectDll(szExeName, szDllPath))
        {
            MessageBox(hwndDlg, "注入成功", "提示",0);
        }
        else {
            MessageBox(hwndDlg, "注入失败", "提示", 0);
        }
    } 
    else if (wParam == BTN_UNINJECT)
    {
        TCHAR szExeName[50];
        TCHAR szDllPath[MAX_PATH];
        GetDlgItemText(hwndDlg, EDIT_PROCESS_NAME, szExeName, sizeof(szExeName));
        GetDlgItemText(hwndDlg, EDIT_DLL_PATH, szDllPath, sizeof(szDllPath));
        if (UninjectDll(szExeName, szDllPath))
        {
            MessageBox(hwndDlg, "卸载成功", "提示", 0);
        }
        else {
            MessageBox(hwndDlg, "卸载失败", "提示", 0);
        }
    }
}

INT_PTR CALLBACK DialogProc(_In_ HWND   hwndDlg, _In_ UINT   uMsg, _In_ WPARAM wParam, _In_ LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_COMMAND:
        {
          OnBtnClicked(hwndDlg, wParam);
           return TRUE;
        }
        case WM_CLOSE: 
        {
             EndDialog(hwndDlg, 0);
             return TRUE;
        }

    }
    return FALSE;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DialogProc);
    return TRUE;
}

