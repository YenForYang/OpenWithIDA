#include<windows.h>
#include<stdio.h>
#include<stdint.h>
#include<errno.h>

enum IMG_STATE : int {
	IS_32BIT = 'L',
	IS_64BIT = 'd',
	INVALID_NT_HEADER_SIG =-1,
	UNIDENTIFIED_FILE =-2,
};

int main(int argc, char* argv[]) {
	if (argc != 2) return -3;


	constexpr auto
		NTHEADER_SIGNATURE    = 0x00004550,
		TARG_APP = 1;

	STARTUPINFOA        si{ sizeof(STARTUPINFOA) /*si.cb, set size.*/ };
	PROCESS_INFORMATION pi;

	constexpr char
		app32[]{ 'i','d','a','.','e','x','e',' ','"' },
		app64[]{ 'i','d','a','6','4','.','e','x','e',' ','"' };
	
	constexpr auto
		cmd32len = sizeof app32 + MAX_PATH,
		cmd64len = sizeof app64 + MAX_PATH;

	switch (
		[&](){ // determine 32 bits or 64 bits
			const auto f = fopen(argv[TARG_APP], "rb");
			if (f == nullptr) {
				perror("Error opening target: ");
				return UNIDENTIFIED_FILE;
			}
			//std::ifstream ifs{argv[TARG_APP]};
			struct {
				u_char MZSignature[2];             // hex, IMAGE_DOS_SIGNATURE = 0x5A4D
				u_char UsedBytesInTheLastPage[2];  // Bytes on last page of file
				u_char FileSizeInPages[2];         // Pages in file
				u_char NumberOfRelocationItems[2]; // Relocations
				u_char HeaderSizeInParagraphs[2];  // Size of header in paragraphs
				u_char MinimumExtraParagraphs[2];  // Minimum extra paragraphs needed
				u_char MaximumExtraParagraphs[2];  // Maximum extra paragraphs needed
				u_char InitialRelativeSS[2];       // Initial (relative) SS value
				u_char InitialSP[2];               // Initial SP value
				u_char Checksum[2];                // Checksum
				u_char InitialIP[2];               // Initial IP value
				u_char InitialRelativeCS[2];       // Initial (relative) CS value
				u_char AddressOfRelocationTable[2];// File address of relocation table
				u_char OverlayNumber[2];           // Overlay number
				u_char Reserved[8];                // Reserved words
				u_char OEMid[2];                   // OEM identifier (for OEMinfo)
				u_char OEMinfo[2];                 // OEM information; OEMid specific
				u_char Reserved2[20];              // Reserved words
				int32_t AddressOfNewExeHeader;     // hex,NtHeader Offset
			} img_dos_header;

			if (fread(&img_dos_header, 1, sizeof img_dos_header, f) != sizeof img_dos_header) {
				perror("Bad target, couldn't read full header");
				return UNIDENTIFIED_FILE;
			}

			fseek(f, img_dos_header.AddressOfNewExeHeader - ftell(f), SEEK_CUR);

			uint32_t sig;
			fread(&sig, sizeof uint32_t, 1, f);
			if (sig != NTHEADER_SIGNATURE) return INVALID_NT_HEADER_SIG;
			//return (IMG_STATE)rbuf->sgetc();
			return (IMG_STATE) fgetc(f);
		}()
	) {
		case IS_32BIT:
			char cmdline32[cmd32len];
			memcpy(cmdline32, app32, sizeof app32);
			memcpy(&cmdline32[sizeof app32], argv[TARG_APP], strlen(argv[TARG_APP])+1);

			return CreateProcessA(
				  NULL,           // the path
				  cmdline32,      // Command line
				  NULL,           // Process handle not inheritable
				  NULL,           // Thread handle not inheritable
				  FALSE,          // Set handle inheritance to FALSE
				  0,              // No creation flags
				  NULL,           // Use parent's environment block
				  NULL,           // Use parent's starting directory 
				  &si,            // Pointer to STARTUPINFO structure
				  &pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
			);

		case IS_64BIT:
			char cmdline64[cmd64len];
			memcpy(cmdline64, app64, sizeof app64);
			memcpy(&cmdline64[sizeof app64], argv[TARG_APP], strlen(argv[TARG_APP])+1);

			return CreateProcessA(
				  NULL,              // the path
				  cmdline64,         // Command line
				  NULL,              // Process handle not inheritable
				  NULL,              // Thread handle not inheritable
				  FALSE,             // Set handle inheritance to FALSE
				  0,                 // No creation flags
				  NULL,              // Use parent's environment block
				  NULL,              // Use parent's starting directory 
				  &si,               // Pointer to STARTUPINFO structure
				  &pi                // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
			);

		case INVALID_NT_HEADER_SIG: return INVALID_NT_HEADER_SIG;
		default: return errno;
	}
}
