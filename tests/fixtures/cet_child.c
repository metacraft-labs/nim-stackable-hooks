/* The real AMD64 entry point exits successfully after the parent resumes it. */
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
void cetChildEntry(void) { ExitProcess(0); }
