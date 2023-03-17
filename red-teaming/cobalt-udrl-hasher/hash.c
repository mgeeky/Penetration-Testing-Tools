//
// Simple utility aimed to help regenerating UDRL hashes
//
// cmd> gcc hash.c -o hash.exe
//
// Mariusz Banach / mgeeky, '23
// binary-offensive.com
//

#include <windows.h>
#include <stdio.h>
#include <intrin.h>

BYTE hashKey = 13;

__forceinline DWORD ror( DWORD d ) {
   return _rotr( d, hashKey );
}

__forceinline DWORD hash( const char * c ) {
   register DWORD h = 0;
   do
   {
      h = ror( h );
      h += *c;
   } while( *++c );

   return h;
}

__forceinline DWORD hashModule( const char * c ) {
   register DWORD h = 0;
   
   size_t counter = strlen(c) * 2;
   wchar_t * wstr = (wchar_t*)malloc(counter + 2);
   char * ptr = (char*)wstr;

   mbstowcs(wstr, c, counter);

   do
   {
      h = ror( (DWORD)h );

      // normalize to uppercase if the module name is in lowercase
      if( *((BYTE *)ptr) >= 'a' )
         h += *((BYTE *)ptr) - 0x20;
      else
         h += *((BYTE *)ptr);

      ptr++;

   } while( --counter );

   free(wstr);
   return h;
}

int endswith(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

void print(char* str) {
   DWORD val = 0;

   if(endswith(str, ".dll")) {
      val = hashModule(str);
   }
   else {
      val = hash(str);
   }

   char str2[256] = "";
   char *s = str2;

   for(int i = 0; i < strlen(str); i++) {
      if(isalnum(str[i])) {
         *(s++) = str[i];
      }
   }

   s = str2;
   while (*s) *(s++) = toupper(*s);

   strncat(str2, "_HASH", sizeof(str2)-1);

   printf("#define %-30s 0x%08X\t// %s\n", str2, val, str);
}

int main(int argc, char** argv) {
   if (argc < 2) {
      printf("Usage: hash.exe <hash_key> [string]\n");
      return 0;
   }

   hashKey = atoi(argv[1]);

   printf("\n");

   if (argc == 3) {
      print(argv[2]);
   }
   else {
      print("kernel32.dll");
      print("ntdll.dll");
      printf("\n");
      print("LoadLibraryA");
      print("GetProcAddress");
      print("VirtualAlloc");
      print("VirtualProtect");
      print("NtFlushInstructionCache");
   }

   printf("\n#define HASH_KEY                       %d\n", hashKey);

   return 0;
}