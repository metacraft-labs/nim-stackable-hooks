// Deterministic pre-main injection point for MSYS2/Cygwin children.
//
// io-mon today does CreateRemoteThread into a CREATE_SUSPENDED child that has
// never executed. The Windows loader then runs LdrpInitializeProcess -- every
// static-import DLL_PROCESS_ATTACH, msys-2.0.dll's included -- ON THAT REMOTE
// THREAD, which then exits. Cygwin's fork() deadlocks afterwards.
//
// This probe instead creates the child under a debug port. The initial
// breakpoint is delivered AFTER LdrpInitializeProcess completed ON THE MAIN
// THREAD and BEFORE the image entry point runs. Suspend the main thread there,
// inject, detach, wait for LoadLibraryW, resume. Deterministic, and no user
// code runs before the shim is mapped.
//
//   usage: dbg_probe.exe <DLL> <child command line ...>
#include <windows.h>
#include <stdio.h>

static void ts(const char *w){SYSTEMTIME s;GetLocalTime(&s);
  fprintf(stderr,"[%02d:%02d:%02d.%03d] %s\n",s.wHour,s.wMinute,s.wSecond,s.wMilliseconds,w);fflush(stderr);}

int wmain(int argc, wchar_t **argv) {
  if (argc < 3) { fprintf(stderr,"usage: dbg_probe DLL cmdline...\n"); return 100; }
  const wchar_t *dll = argv[1];
  wchar_t cmd[32768]; cmd[0]=0;
  for (int i=2;i<argc;i++){ if(i>2) wcscat(cmd,L" "); wcscat(cmd,argv[i]); }
  { char nb[4096]; wcstombs(nb,cmd,sizeof nb); fprintf(stderr,"cmdline: %s\n",nb); }

  STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
  PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
  ts("CreateProcessW(DEBUG_ONLY_THIS_PROCESS)");
  if(!CreateProcessW(NULL,cmd,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,&si,&pi)){
    fprintf(stderr,"CreateProcessW failed err=%lu\n",GetLastError()); return 101; }
  fprintf(stderr,"child pid=%lu\n",pi.dwProcessId);

  BOOL injected=FALSE; DEBUG_EVENT de; int dllEvents=0; HANDLE mainThread=NULL;
  for(;;){
    if(!WaitForDebugEvent(&de,60000)){ ts("WaitForDebugEvent timed out"); return 105; }
    DWORD cont=DBG_CONTINUE;
    if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){
      mainThread=de.u.CreateProcessInfo.hThread;
    } else if(de.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){
      dllEvents++;
    } else if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT &&
              de.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT && !injected){
      fprintf(stderr,"initial breakpoint after %d LOAD_DLL events, tid=%lu (main tid=%lu)\n",
              dllEvents,de.dwThreadId,pi.dwThreadId);
      ts("SuspendThread(main) + inject at initial breakpoint");
      SuspendThread(mainThread);
      SIZE_T bytes=(wcslen(dll)+1)*sizeof(wchar_t);
      LPVOID rb=VirtualAllocEx(pi.hProcess,NULL,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
      SIZE_T wr=0; WriteProcessMemory(pi.hProcess,rb,dll,bytes,&wr);
      FARPROC llw=GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW");
      HANDLE th=CreateRemoteThread(pi.hProcess,NULL,0,(LPTHREAD_START_ROUTINE)llw,rb,0,NULL);
      if(!th){ fprintf(stderr,"CreateRemoteThread failed err=%lu\n",GetLastError()); return 104; }
      injected=TRUE;
      // The debug port freezes the whole process; nothing runs until we
      // continue AND detach. Do that first, then wait for the remote thread.
      ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE);
      if(!DebugActiveProcessStop(pi.dwProcessId))
        fprintf(stderr,"DebugActiveProcessStop failed err=%lu\n",GetLastError());
      ts("detached; waiting for remote LoadLibraryW (main thread still suspended)");
      DWORD w=WaitForSingleObject(th,15000);
      if(w==WAIT_TIMEOUT){ ts("*** remote thread timed out ***"); }
      else { DWORD ex=0; GetExitCodeThread(th,&ex);
             fprintf(stderr,"LoadLibraryW low32=0x%08lX (%s)\n",ex,ex?"loaded":"FAILED");
             VirtualFreeEx(pi.hProcess,rb,0,MEM_RELEASE); }
      CloseHandle(th);
      ts("ResumeThread(main) -- user code starts now, shim already mapped");
      ResumeThread(mainThread);
      break;
    } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){
      fprintf(stderr,"child exited before breakpoint, code=%lu (0x%08lX)\n",
              de.u.ExitProcess.dwExitCode,de.u.ExitProcess.dwExitCode);
      return (int)de.u.ExitProcess.dwExitCode;
    } else if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT) cont=DBG_EXCEPTION_NOT_HANDLED;
    ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont);
  }

  ts("WaitForSingleObject(child,45000)");
  DWORD pw=WaitForSingleObject(pi.hProcess,45000);
  if(pw==WAIT_TIMEOUT){ ts("*** CHILD HUNG ***"); fprintf(stderr,"RESULT: child-hung\n");
    TerminateProcess(pi.hProcess,0xDEAD); return 105; }
  DWORD code=0; GetExitCodeProcess(pi.hProcess,&code);
  fprintf(stderr,"RESULT: child exit code = %lu (0x%08lX)\n",code,code);
  if(code==0xC0000020UL) fprintf(stderr,"*** 0xC0000020 ***\n");
  return (int)code;
}
