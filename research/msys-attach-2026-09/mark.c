#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
static void mark(const char *tag){
  char line[512]; const char *out = getenv("MARK_FILE");
  if(!out) return;
  HANDLE h = CreateFileA(out, FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE,
                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h==INVALID_HANDLE_VALUE) return;
  int n = snprintf(line,sizeof line,"%s pid=%lu base=%p\r\n",tag,GetCurrentProcessId(),
                   (void*)GetModuleHandleA("mark.dll"));
  DWORD w=0; WriteFile(h,line,(DWORD)n,&w,NULL); CloseHandle(h);
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r){
  if(reason==DLL_PROCESS_ATTACH){ DisableThreadLibraryCalls(h); mark("ATTACH"); }
  return TRUE;
}
