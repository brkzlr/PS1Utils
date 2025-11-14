/*
    Copyright (C) 2024 brkzlr <brksys@icloud.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// PlayStation 1 game discs use CD-ROM XA Mode 2, either Form 1 or Form 2 structure with 2352 bytes per sector
#define SECTOR_SIZE 2352
// which consists of (in order):
// Common
#define SECTOR_SYNC_SIZE 12
#define SECTOR_HEADER_SIZE 4 // 3 address, 1 mode
#define SECTOR_SUBHEADER_SIZE 8 // File number / Channel number / Submode / Coding information (repeated for last 4 bytes)
// Form 1
#define SECTOR_FORM1_DATA_SIZE 2048
#define SECTOR_FORM1_ERROR_SIZE 280 // 4 EDC, 276 ECC
// Form 2
#define SECTOR_FORM2_DATA_SIZE 2324
#define SECTOR_FORM2_ERROR_SIZE 4 // EDC only

enum SubmodeBit {
	SB_END_OF_RECORD = 0x01, // Indicates the last sector of a logical record
	SB_VIDEO = 0x02, // Indicates a video sector
	SB_AUDIO = 0x04, // Indicates an audio sector
	SB_DATA = 0x08, // Indicates a data sector
	SB_TRIGGER = 0x10, // Indicates an interrupt to applications
	SB_FORM = 0x20, // Indicates if this sector is form 1 or 2
	SB_REAL_TIME_SECTOR = 0x40, // Indicates if the data has to be processed in real time or not
	SB_END_OF_FILE = 0x80 // Indicates the last sector of a file
};

typedef union {
	uint8_t buffer[SECTOR_SIZE];
	struct {
		uint8_t sync[SECTOR_SYNC_SIZE];
		uint8_t header[SECTOR_HEADER_SIZE];
		uint8_t subheader[SECTOR_SUBHEADER_SIZE];
		uint8_t data[SECTOR_FORM1_DATA_SIZE + SECTOR_FORM1_ERROR_SIZE]; // Both forms have the same data size, just partitioned differently
	};
} Sector_t;

typedef struct {
	uint8_t minutes;
	uint8_t seconds;
	uint8_t sector;
} SectorAddress_t;

static inline bool CheckSubmodeBits(uint8_t submodeByte, uint8_t submodeFlags)
{
	return (submodeByte & submodeFlags) == submodeFlags;
}

static inline uint8_t DecodeBCD(uint8_t binaryCodedDecimal)
{
	return ((binaryCodedDecimal & 0xF0) >> 4) * 10 + (binaryCodedDecimal & 0x0F);
}

static inline uint32_t GetSectorNumber(SectorAddress_t* sectAddr)
{
	// Address is stored as MSB (Minute:Second:Block) with decimal values (BCD)
	// 75 consecutive sectors (blocks) in a CD-ROM second

	// Ignore the first 2 seconds which is the pre-gap of any track
	uint8_t seconds = DecodeBCD(sectAddr->seconds) - 2;
	return (DecodeBCD(sectAddr->minutes) * 60 + seconds) * 75 + DecodeBCD(sectAddr->sector);
}

// Precompute CD-ROM XA CRC32 values to speed things up
static uint32_t crc_table[256];
static inline void CRCTableInit(void)
{
	for (int i = 0; i < 256; ++i) {
		uint32_t edc = i;
		for (int j = 0; j < 8; ++j) {
			edc = (edc >> 1) ^ (edc & 1 ? 0xD8018001 : 0);
		}
		crc_table[i] = edc;
	}
}

static inline uint32_t CalculateEDC(const uint8_t* buffer, size_t length)
{
	// CD-ROMs embed an EDC (Error Detection Code) near the end of sectors
	// This code is a CRC32 checksum which is obtained by applying a modulo 2 polynomial division
	// on subheader + data, the remainder of the division being added after the data part of the sector

	// CRC32 polynomial used as divisor in CD-ROMs is:
	// P(X) = x^32 + x^31 + x^16 + x^15 + x^4 + x^3 + x + 1
	// which is equal to 0x8001801B, but we use reverse bits order which is 0xD8018001

	uint32_t edc = 0u;
	while (length) {
		edc = (edc >> 8) ^ crc_table[(edc ^ (*buffer++)) & 0xFF];
		--length;
	}

	return edc;
}

int main(int argc, char** argv)
{
	bool isVerbose = false;

	const char* fileName = NULL;
	for (size_t i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "-v", 2)) {
			isVerbose = true;
		}
		else {
			fileName = argv[i];
		}
	}

	if (fileName == NULL) {
		printf("Usage: %s [-v for verbose output] <cd_image.bin>\n", argv[0]);
		return 1;
	}

	FILE* file = fopen(fileName, "rb");
	if (!file) {
		printf("Error opening file '%s'\n", fileName);
		return 1;
	}
	CRCTableInit();

	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	bool invalidEDC = false;
	Sector_t sector;
	while (ftell(file) < fileSize) {
		fread(sector.buffer, 1, SECTOR_SIZE, file);

		SectorAddress_t sectAddr = { sector.header[0], sector.header[1], sector.header[2] };
		if (memcmp(sector.sync, "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00", SECTOR_SYNC_SIZE) != 0) {
			// Incorrect sync sector
			printf("Found incorrect sync at address %x:%x:%x, sector: %d\n", sectAddr.minutes, sectAddr.seconds, sectAddr.sector, GetSectorNumber(&sectAddr));
			printf("Please check your bin file for corruption!\n");
			return 1;
		}

		if (sector.header[3] != 0x02) {
			// Make sure it's a PS1 game disc sector which must be Mode 2 XA
			continue;
		}

		const uint8_t formType = CheckSubmodeBits(sector.subheader[2], SB_FORM) + 1; // Form 1 returns false (0), Form 2 returns true (1)
		const uint16_t dataSize = formType == 2 ? SECTOR_FORM2_DATA_SIZE : SECTOR_FORM1_DATA_SIZE;

		uint32_t* crcPtr = (uint32_t*)&sector.data[dataSize];
		uint32_t crc = CalculateEDC(sector.buffer + SECTOR_SYNC_SIZE + SECTOR_HEADER_SIZE, SECTOR_SUBHEADER_SIZE + dataSize);
		if (*crcPtr != crc) {
			invalidEDC = true;
			if (isVerbose) {
				uint32_t sectorNumber = GetSectorNumber(&sectAddr);
				printf("Found mismatch at Sector %d, mode %d, form %d\n", sectorNumber, sector.header[3], formType);
				printf("Found EDC: %X\n", *crcPtr);
				printf("Calculated EDC: %X\n", crc);
			}
			else {
				// We want an early break if we don't care to show what sectors are broken in non-verbose mode
				break;
			}
		}
	}

	if (invalidEDC) {
		printf("Found invalid EDC data!\n");
	}
	else {
		printf("No invalid EDC found!\n");
	}
	fclose(file);
	return 0;
}
