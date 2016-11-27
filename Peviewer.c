#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>

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
DWORD Addr_of_EP = 0;
DWORD PtrIdata = 0;
DWORD ImageBase = 0;
DWORD ImportsVA = 0;
DWORD ImportsSize = 0;
DWORD ImportDirAddr = 0;
//
DWORD Magic = 0;
DWORD SizeofCode = 0;
DWORD EntryPoint = 0;
DWORD Base_Code = 0;
DWORD Image_Base = 0;
DWORD Sec_Alignment = 0;
DWORD File_Alignmet = 0;
DWORD Size_Image = 0;
DWORD Size_Header = 0;
WORD sub_sys = 0;
//
WORD Machine = 0;
DWORD TimeDataStamp = 0;
WORD Size_Of_Opt_Header = 0;
WORD Charateristic = 0;
int NrOfSections = 0; //char buf[NrOfSections][8];
					  //


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
	time_t now;
	char buf[100];
	struct tm *ts;

	if (argc<2) {
		printf("Usage:\nPEviewer.exe FILE.exe");
		return 1;
	}
	LengthofName = strlen(argv[1]);
	if (LengthofName >= LENGTHOFNAME)
	{
		printf("The file name exceeds %d characters.", LENGTHOFNAME);
		return 1;
	}
	printf("File Name\t:\t %s\n", argv[1]);

	FILE* p;

	fopen_s(&p, argv[1], "rb");
	if (p == NULL) {
		perror("Cannot open the file test.exe");
		return 2;
	}
	puts("File opened successfully");
	fseek(p, 0, SEEK_END);
	Size_Of_File = ftell(p);  // File size calc.
	printf("File Size\t:\t%d byte\n", Size_Of_File);

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
	SectionInfo * sinfo = (SectionInfo *)malloc(sizeof(SectionInfo)*NrOfSections);
	Size_Of_Opt_Header = FileHeader.SizeOfOptionalHeader;
	//fseek(p,Size_Of_Opt_Header,SEEK_CUR);        // move the section header
	fread(&OptionalHeader, 1, Size_Of_Opt_Header, p);
	Addr_of_EP = OptionalHeader.AddressOfEntryPoint;
	ImportsVA = OptionalHeader.DataDirectory[1].VirtualAddress;   // Address of Import Directory in memory
	ImportsSize = OptionalHeader.DataDirectory[1].Size;          // size of Import Directory in memory
	ImageBase = OptionalHeader.ImageBase;

	//printf("# of Sections: %d\n", NrOfSections);
	//printf("Size of Optional Header is: %d\n", Size_Of_Opt_Header);
	//printf("# of subsystem: %d\n", subsys);    // 1 : Driver File(*.sys),  2 : GUI(GRaphic User Interface -> Notepad.exe), 3 : CUI(COnsole User Interface) -> cmd.exe
	//printf("Address of entry point: %lx\n", Addr_of_EP);
	//printf("Virtual Address of Import table %lx\n", ImportsVA);
	//printf("Import table size %lx\n", ImportsSize);
	//printf("ImageBase equals %lx\n\n", ImageBase);

	//NT Header Information 출력
	printf("---------------------------------------------------\n");
	printf("----------------NT Header Information--------------\n");


	Machine = FileHeader.Machine;
	TimeDataStamp = FileHeader.TimeDateStamp;
	Charateristic = FileHeader.Characteristics;

	printf("Machine\t\t\t:\t %#lx \t\t //파일 동작하는 CPU \n", Machine); //IA32: 0x14c, IA64 :0x200
	printf("NumberOfSections\t:\t %#lx \t\t //섹션의 수  \n", NrOfSections); //16진수 -> 10진수 변환
	printf("TimeDataStamp\t\t:\t %d \t //만들어진 시간\n", TimeDataStamp); //Timestamp -> Date 변환
	printf("SizeOfOptionalHeader\t:\t %#lx \t\t //Optional Header 크기 \n", Size_Of_Opt_Header);
	printf("Charateristic\t\t:\t %#lx \t\t //파일의 형식 \n", Charateristic); //0x102-32bit ,

																		 // Optional Header Information 출력
	printf("---------------------------------------------------\n");
	printf("----------Optional Header Information-------------- \n");


	Magic = OptionalHeader.Magic; //Optional Header 종류
	SizeofCode = OptionalHeader.SizeOfCode; //코드섹션크기
	EntryPoint = OptionalHeader.AddressOfEntryPoint; //Entry Point
	Base_Code = OptionalHeader.BaseOfCode; //코드 영역 주소
	Image_Base = OptionalHeader.ImageBase; //RVA 기준점
	Sec_Alignment = OptionalHeader.SectionAlignment; //섹션단위
	File_Alignmet = OptionalHeader.FileAlignment; //파일단위
	Size_Image = OptionalHeader.SizeOfImage; //메모리 로딩 시의 크기
	Size_Header = OptionalHeader.SizeOfHeaders; // 헤더 크기
	sub_sys = OptionalHeader.Subsystem; //파일 종류

	printf("Magic\t\t\t:\t %#lx \t\t //Optional Header 종류 \n", Magic);
	printf("Size Of Code\t\t:\t %#lx \t //코드 섹션 크기  \n", SizeofCode);
	printf("Entry Point\t\t:\t %#lx \t //처음 실행 코드 주소\n", EntryPoint);
	printf("Base of Code\t\t:\t %#lx \t //코드 영역 주소 \n", Base_Code);
	printf("Image Base\t\t:\t %#lx \t //RVA 기준점 \n", ImageBase);
	printf("Section Alignment\t:\t %#lx \t //섹션 단위 \n", Sec_Alignment);
	printf("File Alignment\t\t:\t %#lx \t\t //파일 단위 \n", File_Alignmet);
	printf("Size of Image\t\t:\t %#lx \t //메모리 로딩 시의 크기 \n", Size_Image);
	printf("Size of Header\t\t:\t %#lx \t\t //헤더크기 \n", Size_Header);
	printf("Sub system\t\t:\t %#lx \t\t //파일종류 \n", sub_sys); //0x0002 EXE , 0x2000 DLL

	printf("---------------------------------------------------\n");



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
		print_section(&sinfo[i]);

		/*if(strcmp(".idata",sinfo[i].name)==0){
		puts("Match\n");
		PtrIdata = SectionHeader.PointerToRawData;
		printf("Pointer to .idata section: %lx\n", PtrIdata);
		}*/

		i++;
	} while (i<NrOfSections);

	//ImportDirAddr = ImportsVA-SectVA+SectPtrRAW;

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

	DWORD filename;

	puts("\nList of imported dll's\n");
	for (i = 0; i<(count - 1); i++) {
		filename = RAW2offset(Imported[i].Name, sinfo);  //convert RAV address of INT to file offset
		fseek(p, filename, SEEK_SET);
		do {
			int c;
			c = fgetc(p);
			if (c == 0) {
				printf("\n");
				break;
			}
			printf("%c", c);
		} while (1);

	}
	fclose(p);
	return 0;
}