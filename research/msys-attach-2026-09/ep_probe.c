// Deterministic, race-free pre-main injection for MSYS2/Cygwin children.
//
//   1. CreateProcessW(CREATE_SUSPENDED)
//   2. Patch the image entry point with `EB FE` (jmp $)
//   3. ResumeThread -- the LOADER now runs LdrpInitializeProcess ON THE MAIN
//      THREAD (this is the part io-mon gets wrong today), then jumps to the
//      entry point and spins there. No user code has run.
//   4. Poll GetThreadContext until RIP == entry point  => process fully
//      initialized, loader lock released, main thread parked.
//   5. SuspendThread(main); CreateRemoteThread(LoadLibraryW); wait.
//   6. Restore the two original bytes, FlushInstructionCache, ResumeThread.
//
//   usage: ep_probe.exe <DLL-or-NONE> <child command line ...>
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef struct { NTSTATUS ExitStatus; PVOID PebBaseAddress; ULONG_PTR AffinityMask;
                 LONG BasePriority; ULONG_PTR UniqueProcessId; ULONG_PTR ParentPid; } PBI;
typedef NTSTATUS (NTAPI *PFN_NTQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);

static void ts(const char *w){SYSTEMTIME s;GetLocalTime(&s);
  fprintf(stderr,"[%02d:%02d:%02d.%03d] %s\n",s.wHour,s.wMinute,s.wSecond,s.wMilliseconds,w);fflush(stderr);}

int wmain(int argc, wchar_t **argv){
  if(argc<3){ fprintf(stderr,"usage: ep_probe DLL cmdline...\n"); return 100; }
  const wchar_t *dll=argv[1];
  BOOL doInject = wcscmp(dll,L"NONE")!=0;
  wchar_t cmd[32768]; cmd[0]=0;
  for(int i=2;i<argc;i++){ if(i>2) wcscat(cmd,L" "); wcscat(cmd,argv[i]); }
  { char nb[4096]; wcstombs(nb,cmd,sizeof nb); fprintf(stderr,"cmdline: %s\n",nb); }

  STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
  PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
  ts("CreateProcessW(CREATE_SUSPENDED)");
  if(!CreateProcessW(NULL,cmd,NULL,NULL,TRUE,CREATE_SUSPENDED,NULL,NULL,&si,&pi)){
    fprintf(stderr,"CreateProcessW failed err=%lu\n",GetLastError()); return 101; }
  fprintf(stderr,"child pid=%lu\n",pi.dwProcessId);

  // --- locate the image entry point via the child's PEB --------------------
  PFN_NTQIP NtQIP=(PFN_NTQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess");
  PBI pbi; ULONG rl=0;
  if(NtQIP(pi.hProcess,0,&pbi,sizeof pbi,&rl)!=0){ fprintf(stderr,"NtQueryInformationProcess failed\n"); return 102; }
  BYTE *imageBase=NULL; SIZE_T got=0;
  ReadProcessMemory(pi.hProcess,(BYTE*)pbi.PebBaseAddress+0x10,&imageBase,sizeof imageBase,&got);
  LONG lfanew=0; ReadProcessMemory(pi.hProcess,imageBase+0x3C,&lfanew,4,&got);
  DWORD entryRva=0; ReadProcessMemory(pi.hProcess,imageBase+lfanew+0x28,&entryRva,4,&got);
  BYTE *entry=imageBase+entryRva;
  fprintf(stderr,"image base=%p entry rva=0x%lX entry=%p\n",imageBase,entryRva,entry);

  BYTE orig[2]; ReadProcessMemory(pi.hProcess,entry,orig,2,&got);
  BYTE spin[2]={0xEB,0xFE};
  DWORD oldProt=0;
  VirtualProtectEx(pi.hProcess,entry,2,PAGE_EXECUTE_READWRITE,&oldProt);
  if(!WriteProcessMemory(pi.hProcess,entry,spin,2,&got)){
    fprintf(stderr,"patch entry failed err=%lu\n",GetLastError()); return 103; }
  fprintf(stderr,"entry patched: %02X %02X -> EB FE\n",orig[0],orig[1]);

  ts("ResumeThread -- loader initializes ON THE MAIN THREAD");
  ResumeThread(pi.hThread);

  // --- wait until the main thread is parked at the entry point -------------
  CONTEXT c; ZeroMemory(&c,sizeof c); c.ContextFlags=CONTEXT_CONTROL;
  int spins=0; BOOL parked=FALSE;
  for(int i=0;i<20000;i++){
    if(GetThreadContext(pi.hThread,&c) && c.Rip==(DWORD64)(ULONG_PTR)entry){ parked=TRUE; spins=i; break; }
    Sleep(1);
  }
  if(!parked){ fprintf(stderr,"main thread never parked at entry (last RIP=0x%llX)\n",(unsigned long long)c.Rip); return 104; }
  fprintf(stderr,"main thread parked at entry after %d ms -- loader done, lock free\n",spins);

  if(doInject){
    ts("SuspendThread(main) + inject");
    SuspendThread(pi.hThread);
    SIZE_T bytes=(wcslen(dll)+1)*sizeof(wchar_t);
    LPVOID rb=VirtualAllocEx(pi.hProcess,NULL,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    SIZE_T wr=0; WriteProcessMemory(pi.hProcess,rb,dll,bytes,&wr);
    FARPROC llw=GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW");
    HANDLE th=CreateRemoteThread(pi.hProcess,NULL,0,(LPTHREAD_START_ROUTINE)llw,rb,0,NULL);
    if(!th){ fprintf(stderr,"CreateRemoteThread failed err=%lu\n",GetLastError()); return 105; }
    DWORD w=WaitForSingleObject(th,15000);
    if(w==WAIT_TIMEOUT) ts("*** remote thread timed out ***");
    else { DWORD ex=0; GetExitCodeThread(th,&ex);
           fprintf(stderr,"LoadLibraryW low32=0x%08lX (%s)\n",ex,ex?"loaded":"FAILED");
           VirtualFreeEx(pi.hProcess,rb,0,MEM_RELEASE); }
    CloseHandle(th);
  }

  ts("restore entry bytes + resume");
  WriteProcessMemory(pi.hProcess,entry,orig,2,&got);
  VirtualProtectEx(pi.hProcess,entry,2,oldProt,&oldProt);
  FlushInstructionCache(pi.hProcess,entry,2);
  if(doInject) ResumeThread(pi.hThread);

  ts("WaitForSingleObject(child,45000)");
  DWORD pw=WaitForSingleObject(pi.hProcess,45000);
  if(pw==WAIT_TIMEOUT){ ts("*** CHILD HUNG ***"); fprintf(stderr,"RESULT: child-hung\n");
    TerminateProcess(pi.hProcess,0xDEAD); return 105; }
  DWORD code=0; GetExitCodeProcess(pi.hProcess,&code);
  fprintf(stderr,"RESULT: child exit code = %lu (0x%08lX)\n",code,code);
  if(code==0xC0000020UL) fprintf(stderr,"*** 0xC0000020 ***\n");
  return (int)code;
}
