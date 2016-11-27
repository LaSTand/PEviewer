#include <stdio.h>
#include <string.h>
#include <windows.h>

#define PE "It is not a PE file\n"
#define LENGTHOFNAME 20
IMAGE_DOS_HEADER DosHeader;
IMAGE_FILE_HEADER FileHeader;
IMAGE_SECTION_HEADER SectionHeader;
IMAGE_OPTIONAL_HEADER32 OptionalHeader;
IMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
DWORD PointerToPeHeader = 0;
DWORD Size_Of_File = 0;
DWORD Pe_Signature = 0;
WORD Size_Of_Opt_Header = 0;
WORD subsys = 0;
DWORD Addr_of_EP = 0;
DWORD PtrIdata = 0;
DWORD ImageBase = 0;
DWORD ImportsVA = 0;
DWORD ImportsSize = 0;
DWORD ImportDirAddr = 0;
int NrOfSections = 0;
//char buf[NrOfSections][8];

typedef struct _SectionInfo {
	char name[10];
	int VA;
	int VirtualSize;
	int SizeOfRAW;
	int Ptr2RAW;
	DWORD characteristics;
} SectionInfo;

void print_section(SectionInfo *sinfo) {    //print the value that section structure
	printf("%s\n", sinfo->name);
	printf("\tVirtual Address : %x\n", sinfo->VA);
	printf("\tVirtual Size : %x\n", sinfo->VirtualSize);
	printf("\tPointer To Raw Data : %x\n", sinfo->Ptr2RAW);
	printf("\tSize of Raw Data : %x\n", sinfo->SizeOfRAW);
	printf("\tCharacteristics : %lx\n", sinfo->characteristics);
}

int RAW2offset(int input, SectionInfo * sinfo) {  //Change the RVA of input  -> File Offset
	int i;
	int output = 0;
	for (i = 0; i<NrOfSections; i++) {
		if ((input >= sinfo[i].VA) && (input <= (sinfo[i].VirtualSize + sinfo[i].VA))) {
			output = input - sinfo[i].VA + sinfo[i].Ptr2RAW;
			return output;
		}

	}
	return -1;
}

int main(int argc, char *argv[])
{
	int LengthofName;
	int j = 0;
	if (argc<2) {
		printf("Usage:\nPEviewer.exe FILE.exe");
		return 1;
	}
	LengthofName = strlen(argv[1]);
	if (LengthofName >= LENGTHOFNAME) {
		printf("The file name exceeds %d characters.", LENGTHOFNAME);
		return 1;
	}
	printf("##########################################\n");
	printf("Opened the file: %s\n", argv[1]);

	FILE* p;

	fopen_s(&p, argv[1], "rb");
	if (p == NULL) {
		perror("Cannot open the file test.exe");
		return 2;
	}
	puts("File opened successfully");
	fseek(p, 0, SEEK_END);
	Size_Of_File = ftell(p);  // File size calc.
	printf("File Size : %d byte\n", Size_Of_File);

	fseek(p, 0, SEEK_SET);
	fread(&DosHeader, 1, sizeof(DosHeader), p);

	if (DosHeader.e_magic != 'M' + 'Z' * 256) {  // check Dos Signature
		printf(PE);
		fclose(p);
		return -1;
	}

	PointerToPeHeader = DosHeader.e_lfanew;
	printf("PE header available at: %lx\n", PointerToPeHeader);
	fseek(p, PointerToPeHeader, SEEK_SET);
	fread(&Pe_Signature, 1, sizeof(Pe_Signature), p);             // NT Header 


	if (Pe_Signature != 'P' + 'E' * 256) {                   // check the signature
		printf(PE);
		fclose(p);
		return -1;
	}

	fread(&FileHeader, 1, sizeof(FileHeader), p);          // IMAGE_FILE_HEADER
	NrOfSections = FileHeader.NumberOfSections;
	printf("# of Sections: %d\n", NrOfSections);

	SectionInfo * sinfo = (SectionInfo *)malloc(sizeof(SectionInfo)*NrOfSections);
	Size_Of_Opt_Header = FileHeader.SizeOfOptionalHeader;
	printf("Size of Optional Header is: %d\n", Size_Of_Opt_Header);

	//fseek(p,Size_Of_Opt_Header,SEEK_CUR);        // move the section header
	fread(&OptionalHeader, 1, Size_Of_Opt_Header, p);
	subsys = OptionalHeader.Subsystem;
	printf("# of subsystem: %d\n", subsys);    // 1 : Driver File(*.sys),  2 : GUI(GRaphic User Interface -> Notepad.exe), 3 : CUI(COnsole User Interface) -> cmd.exe
	Addr_of_EP = OptionalHeader.AddressOfEntryPoint;
	printf("Address of entry point: %lx\n", Addr_of_EP);

	ImportsVA = OptionalHeader.DataDirectory[1].VirtualAddress;   // Address of Import Directory in memory
	ImportsSize = OptionalHeader.DataDirectory[1].Size;          // size of Import Directory in memory
	printf("Virtual Address of Import table %lx\n", ImportsVA);
	printf("Import table size %lx\n", ImportsSize);
	ImageBase = OptionalHeader.ImageBase;
	printf("ImageBase equals %lx\n\n", ImageBase);
	printf("##########################################\n");
	// Section Header
	int i = 0;
	do {                                                   // Section information output
		fread(&SectionHeader, 1, sizeof(SectionHeader), p);
		memcpy(sinfo[i].name, SectionHeader.Name, 10);
		sinfo[i].VA = SectionHeader.VirtualAddress;
		sinfo[i].VirtualSize = SectionHeader.Misc.VirtualSize;
		sinfo[i].SizeOfRAW = SectionHeader.SizeOfRawData;
		sinfo[i].Ptr2RAW = SectionHeader.PointerToRawData;
		sinfo[i].characteristics = SectionHeader.Characteristics;
		//print_section(&sinfo[i]);
		printf("%d. %s\n", i, sinfo[i].name);
		/*if(strcmp(".idata",sinfo[i].name)==0){
		puts("Match\n");
		PtrIdata = SectionHeader.PointerToRawData;
		printf("Pointer to .idata section: %lx\n", PtrIdata);
		}*/

		i++;
	} while (i<NrOfSections);
	printf("%d. .전체\n", i);
	printf("##########################################\n");
	printf("입력:");
	scanf("%d", &j);
	if (j != i)
		print_section(&sinfo[j]);
	else {
		for (i = 0; i < NrOfSections; i++)
			print_section(&sinfo[i]);
	}
	//ImportDirAddr = ImportsVA-SectVA+SectPtrRAW;
	printf("##########################################\n");
	ImportDirAddr = RAW2offset(ImportsVA, sinfo);  // Raw offset address of ImportDirAddr
	printf("\nImports at %lx\n", ImportDirAddr);
	fseek(p, ImportDirAddr, SEEK_SET);
	fread(&ImportDescriptor, 1, 20, p); //read the first IMPORT descriptor
	int count = 1;
	while (ImportDescriptor.Name != 0) {         // Import TABLE count
		fread(&ImportDescriptor, 1, 20, p);
		count++;
	}
	IMAGE_IMPORT_DESCRIPTOR * Imported = (IMAGE_IMPORT_DESCRIPTOR *)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR)*(count - 1));
	fseek(p, ImportDirAddr, SEEK_SET);

	for (i = 0; i<(count - 1); i++) {
		fread(&Imported[i], 1, 20, p);
		printf("[%d] Import Descriptor Name at %lx\n", i, Imported[i].Name);  // RAV address of IMPORT NAME TABLE 
	}
	DWORD filename, func_name;
	long * filename_pos, func_name_pos;
	filename_pos = (long *)malloc(sizeof(long)*(count)-1);
	printf("\n##########################################\n");
	puts("\nList of imported dll's\n");
	for (i = 0; i<(count - 1); i++) {
		filename = RAW2offset(Imported[i].Name, sinfo);  //convert RAV address of INT to file offset
		fseek(p, filename, SEEK_SET);
		filename_pos[i] = ftell(p);
		do {
			int c;
			c = fgetc(p);
			if (c == 0) {
				printf("\n");
				break;
			}
			printf("%c", c);
		} while (1);
		//printf("\taddress:%lx\n", filename);
		func_name = RAW2offset(Imported[i].FirstThunk, sinfo); // [-] function output starting, incomplete...
		fseek(p, func_name, SEEK_SET);
		fread(&func_name, 1, sizeof(func_name), p);
		func_name = RAW2offset(func_name, sinfo);

		while (func_name == 0xffffffff) // RVA chekcing
		{
			fread(&func_name, 1, sizeof(func_name), p);
			//printf("\t\t\t one function address in INT RVA: %lx\n", func_name);
			func_name = RAW2offset(func_name, sinfo);
		}
		func_name_pos = ftell(p);
		fseek(p, func_name, SEEK_SET);
		fgetc(p); fgetc(p); printf("\t\t");

		int temp, j = 1;
		while (filename_pos[i] - 2>func_name_pos)
		{
			int c;
			c = fgetc(p);
			if (j == 1)
			{
				temp = c;
			}
			if (isalpha(c) || (c == 0x5f) || (c >= 0x30 && c <= 0x39))  //short cut, 대소문자 또는 _ 로 시작하는지 확인
			{
				printf("%c", c);
			}
			else
			{
				if (c == 0x00 && temp != 0x00)
				{
					printf("()\n\t\t");
					fgetc(p); fgetc(p);
				}
				do
				{
					c = fgetc(p);
				} while (!(isalpha(c) || (c == 0x5f) || (c >= 0x30 && c <= 0x39)));
				printf("%c", c);

			}
			temp = c;
			func_name_pos = ftell(p);
			j++;
		}
		printf("()\n");
	}
	fclose(p);
	return 0;
}
