// Reproduction ladder for io-mon's CreateProcessW child-injection path.
//   usage: inject_probe.exe <MODE> <DLL-or-NONE> <child command line ...>
// MODES
//   plain      : CreateProcessW, no CREATE_SUSPENDED, no injection
//   susp       : CREATE_SUSPENDED + ResumeThread, no injection
//   inject     : CREATE_SUSPENDED + remote LoadLibraryW(DLL) + ResumeThread   (io-mon today)
//   injectfree : as inject, but VirtualFreeEx the remote path buffer first
//   thread     : CREATE_SUSPENDED + remote thread running kernel32!GetCurrentProcessId
//                (NO LoadLibrary, NO new section, NO leftover buffer) + ResumeThread
//   alloc      : CREATE_SUSPENDED + VirtualAllocEx only (no thread) + ResumeThread
//   post       : ResumeThread first, sleep DELAY ms, THEN remote LoadLibraryW(DLL)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static void ts(const char *what) {
  SYSTEMTIME st; GetLocalTime(&st);
  fprintf(stderr, "[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute,
          st.wSecond, st.wMilliseconds, what);
  fflush(stderr);
}

static HANDLE gProc;
static LPVOID gBuf;

static int remoteLoadLibrary(const wchar_t *dll, BOOL freeBuf) {
  SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
  gBuf = VirtualAllocEx(gProc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!gBuf) { fprintf(stderr, "VirtualAllocEx failed err=%lu\n", GetLastError()); return -1; }
  fprintf(stderr, "remote buf = %p\n", gBuf);
  SIZE_T wrote = 0;
  if (!WriteProcessMemory(gProc, gBuf, dll, bytes, &wrote)) {
    fprintf(stderr, "WriteProcessMemory failed err=%lu\n", GetLastError()); return -1; }
  FARPROC llw = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  ts("CreateRemoteThread(LoadLibraryW)");
  HANDLE th = CreateRemoteThread(gProc, NULL, 0, (LPTHREAD_START_ROUTINE)llw, gBuf, 0, NULL);
  if (!th) { fprintf(stderr, "CreateRemoteThread failed err=%lu\n", GetLastError()); return -1; }
  DWORD w = WaitForSingleObject(th, 15000);
  if (w == WAIT_TIMEOUT) { ts("*** REMOTE THREAD TIMED OUT (deadlock in LoadLibraryW) ***"); }
  else { DWORD ex = 1; GetExitCodeThread(th, &ex);
         fprintf(stderr, "remote thread returned, LoadLibraryW low32=0x%08lX (%s)\n",
                 ex, ex ? "loaded" : "FAILED"); }
  CloseHandle(th);
  if (freeBuf) { VirtualFreeEx(gProc, gBuf, 0, MEM_RELEASE); ts("VirtualFreeEx(remote buf)"); }
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  if (argc < 4) { fprintf(stderr, "usage: inject_probe MODE DLL cmdline...\n"); return 100; }
  const wchar_t *mode = argv[1];
  const wchar_t *dll  = argv[2];
  wchar_t cmd[32768]; cmd[0] = 0;
  for (int i = 3; i < argc; i++) { if (i > 3) wcscat(cmd, L" "); wcscat(cmd, argv[i]); }
  { char nb[4096]; wcstombs(nb, cmd, sizeof nb); fprintf(stderr, "MODE=%ls cmdline: %s\n", mode, nb); }

  BOOL doSusp = (wcscmp(mode, L"plain") != 0);
  STARTUPINFOW si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
  PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);
  ts("CreateProcessW");
  if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, doSusp ? CREATE_SUSPENDED : 0,
                      NULL, NULL, &si, &pi)) {
    fprintf(stderr, "CreateProcessW failed err=%lu\n", GetLastError()); return 101; }
  gProc = pi.hProcess;
  fprintf(stderr, "child pid=%lu suspended=%d\n", pi.dwProcessId, doSusp);

  if (!wcscmp(mode, L"inject"))     { if (remoteLoadLibrary(dll, FALSE)) return 102; }
  if (!wcscmp(mode, L"injectfree")) { if (remoteLoadLibrary(dll, TRUE))  return 102; }
  if (!wcscmp(mode, L"alloc")) {
    LPVOID b = VirtualAllocEx(gProc, NULL, 65536, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    fprintf(stderr, "alloc-only remote buf = %p\n", b);
  }
  if (!wcscmp(mode, L"thread")) {
    FARPROC f = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCurrentProcessId");
    ts("CreateRemoteThread(GetCurrentProcessId) -- no LoadLibrary, no new section");
    HANDLE th = CreateRemoteThread(gProc, NULL, 0, (LPTHREAD_START_ROUTINE)f, NULL, 0, NULL);
    if (!th) { fprintf(stderr, "CreateRemoteThread failed err=%lu\n", GetLastError()); return 104; }
    DWORD w = WaitForSingleObject(th, 15000);
    if (w == WAIT_TIMEOUT) ts("*** BARE REMOTE THREAD TIMED OUT ***");
    else { DWORD ex=0; GetExitCodeThread(th,&ex); fprintf(stderr,"bare remote thread returned %lu\n", ex); }
    CloseHandle(th);
  }

  if (doSusp) { ts("ResumeThread"); ResumeThread(pi.hThread); }

  if (!wcscmp(mode, L"post")) {
    { const char *d = getenv("PROBE_DELAY_MS");
      int ms = d ? atoi(d) : 400;
      fprintf(stderr, "post delay = %d ms\n", ms);
      Sleep(ms); }
    ts("post-resume injection now");
    if (remoteLoadLibrary(dll, FALSE)) return 102;
  }

  ts("WaitForSingleObject(child, 45000ms)");
  DWORD pw = WaitForSingleObject(pi.hProcess, 45000);
  if (pw == WAIT_TIMEOUT) {
    ts("*** CHILD PROCESS TIMED OUT -- HUNG ***");
    fprintf(stderr, "RESULT: child-hung\n");
    TerminateProcess(pi.hProcess, 0xDEAD); return 105;
  }
  DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
  fprintf(stderr, "RESULT: child exit code = %lu (0x%08lX)\n", code, code);
  if (code == 0xC0000020UL) fprintf(stderr, "*** 0xC0000020 STATUS_INVALID_FILE_FOR_SECTION ***\n");
  return (int)code;
}
