/*
        Copyright (C) 2025 brkzlr <brksys@icloud.com>

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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CTR 0
#define CBC 0
#include "aes.h"
#include "sha1.h"

#define SALT_SIZE 0x14
#define HASH_SIZE 0x14
#define MAX_SAVE_BLOCKS 0xF

// All of the fields below are array type to guarantee a packed struct with no padding in a portable way.
// Otherwise having some of them as uint32_t would've been more helpful.
typedef struct {
	uint8_t magic[0x08]; // PSV magic string stored as "\0VSP"
	uint8_t salt[SALT_SIZE]; // AES-128 encrypted salt key for the HMAC-SHA1 hash below
	uint8_t hash[HASH_SIZE]; // HMAC-SHA1 used to sign/verify the PSV against corruption/tampering
	uint8_t padding1[0x08]; // Always 0
	uint8_t headerSize[0x04]; // 0x14 for PS1, 0x2C for PS2
	uint8_t type[0x04]; // 0x01 for PS1, 0x02 for PS2
	uint8_t saveSize[0x04]; // Always a multiple of 0x2000 (8192) bytes for PS1
	uint8_t slotStartOffset[0x04]; // First slot start offset from file start, always 0x84 for PS1
	uint8_t dataStartOffset[0x04]; // Save data offset from slot start, always 0x200 for PS1
	uint8_t padding2[0x10]; // Always 0
	uint8_t saveSizeDup[0x04]; // Same as saveSize, duplicate or maybe something else?
	uint8_t unknown[0x04]; // Always 9003, not sure what this is
	uint8_t fileName[0x14]; // Game ID (eg. BASLUS-00707) + Save Description (eg. SILENT00)
	uint8_t padding3[0x0C]; // Always 0
} PSVHeader_t; // Size 0x84 bytes

// Fields are not used directly but still here for documentation purposes
typedef struct {
	uint8_t magic[0x02]; // Always "SC" if block is the start of a new save, otherwise everything in this block is used as continuous save data
	uint8_t iconDisplayFlag; // 0x11 for static 1 frame icon, 0x12 = 2 frames animated, 0x13 = 3 frames animated
	uint8_t blockCount; // Most saves are one "icon" so 0x1, otherwise they're linked using DirectoryBlock_t info and count specified here
	uint8_t saveTitle[0x40]; // Stored in Shift-JIS format
	uint8_t reserved[0x0C]; // Always 0
	uint8_t reservedPocket[0x10]; // Actually split into 3 internal fields but we don't care about the PocketStation so it's all 0s
	uint8_t iconPalette[0x20]; // 16 colour palette data, 16bit CLUT format
	uint8_t icon[0x80]; // Bitmap data, 16x16 with 4bits colour depth
	uint8_t iconAnim1[0x80]; // Second frame bitmap data, used if iconDisplayFlag is 0x12 or 0x13
	uint8_t iconAnim2[0x80]; // Third frame bitmap data, used if iconDisplayFlag is 0x13
	uint8_t data[0x1E00]; // Actual save data
} SaveBlock_t; // Size 8192 (0x2000) bytes

typedef struct {
	PSVHeader_t header;
	SaveBlock_t save[]; // PSV files always store one save but one save can contain multiple blocks, up to 15
} PSVFile_t;

static void CalcSHA1HMAC(uint8_t* digest, const uint8_t* data, size_t dataLen, const uint8_t* key, size_t keyLen)
{
	// This algorithm requires the key to be hashed beforehand if it surpasses 64 bytes before padding
	// but PSV and VMP have the key capped to 20 bytes so no need for this step.

	// To obtain HMAC's first pass inner key, we use a 64 bytes 0x36 pad and XOR it with our <=64 bytes key.
	uint8_t paddedKey[64];
	memset(paddedKey, 0x36, 64);
	for (size_t i = 0; i < keyLen; ++i) {
		paddedKey[i] ^= *(key + i);
	}

	// Add the inner key to message and hash them together.
	SHA1_CTX shaCtx;
	SHA1Init(&shaCtx);
	SHA1Update(&shaCtx, paddedKey, 64);
	SHA1Update(&shaCtx, data, dataLen);

	uint8_t innerHash[20];
	SHA1Final(innerHash, &shaCtx);

	// Create second step's outer key, which uses a 0x5c pad.
	memset(paddedKey, 0x5c, 64);
	for (size_t i = 0; i < keyLen; ++i) {
		paddedKey[i] ^= *(key + i);
	}

	// Add the outer key to the inner hash and obtain the final digest.
	SHA1Init(&shaCtx);
	SHA1Update(&shaCtx, paddedKey, 64);
	SHA1Update(&shaCtx, innerHash, 20);
	SHA1Final(digest, &shaCtx);
}

static void SignFile(uint8_t* digest, const uint8_t* buffer, size_t bufferLen, const uint8_t* salt)
{
	// Thank you to dots-tb: https://github.com/dots-tb/ps3-psvresigner/blob/e4905bfc65d4126eb7c1460e0b32bceffbff8a6e/src/main.c#L24
	// Though I have no idea where they pulled the key and IV from. Tried looking into PS3 key dumps myself but no luck.
	static uint8_t aesIv[16] = { 0xB3, 0x0F, 0xFE, 0xED, 0xB7, 0xDC, 0x5E, 0xB7, 0x13, 0x3D, 0xA6, 0x0D, 0x1B, 0x6B, 0x2C, 0xDC };
	static uint8_t aesKey[16] = { 0xAB, 0x5A, 0xBC, 0x9F, 0xC1, 0xF4, 0x9D, 0xE6, 0xA0, 0x51, 0xDB, 0xAE, 0xFA, 0x51, 0x88, 0x59 };

	// For some reason that I still don't understand, PS2 PSV uses AES-CBC for key salt decryption but PS1 uses a weird variant of AES-EBC.
	// Tried adapting the CBC algorithm myself and change stuff to make it work but it doesn't.
	// Did Sony really use different AES algorithms for PS1/PS2 and why?
	uint8_t finalSalt[AES_BLOCKLEN * 2];

	struct AES_ctx aesCtx;
	AES_init_ctx(&aesCtx, aesKey);

	uint8_t workBuf[AES_BLOCKLEN];
	memcpy(workBuf, salt, AES_BLOCKLEN);
	AES_ECB_decrypt(&aesCtx, workBuf);
	memcpy(finalSalt, workBuf, AES_BLOCKLEN);

	memcpy(workBuf, salt, AES_BLOCKLEN);
	AES_ECB_encrypt(&aesCtx, workBuf);
	memcpy(finalSalt + 0x10, workBuf, AES_BLOCKLEN);

	for (uint8_t i = 0; i < AES_BLOCKLEN; ++i) {
		finalSalt[i] ^= aesIv[i];
	}

	memset(workBuf, 0xFF, AES_BLOCKLEN);
	memcpy(workBuf, salt + 0x10, SALT_SIZE - 0x10);
	for (uint8_t i = 0; i < AES_BLOCKLEN; ++i) {
		finalSalt[0x10 + i] ^= workBuf[i];
	}

	CalcSHA1HMAC(digest, buffer, bufferLen, finalSalt, SALT_SIZE);
}

static void CreatePSVFromSave(FILE* file, const char* fileName, size_t blockCount)
{
	const size_t cPSVSize = sizeof(PSVHeader_t) + sizeof(SaveBlock_t) * blockCount;

	// Create our virtual PSV and copy the PS1 save into the save container
	PSVFile_t* psvFile = (PSVFile_t*)calloc(1, cPSVSize);
	fread(&psvFile->save, sizeof(SaveBlock_t), blockCount, file);

	// Fill in necessary header data.
	memcpy(psvFile->header.magic, "\0VSP", 4);
	memcpy(psvFile->header.salt, "brkzlrwuzhere", 13); // Create a random key salt as the PS3 doesn't care about the specific salt value
	psvFile->header.headerSize[0] = 0x14; // Set byte directly with endianness in mind to avoid casting
	psvFile->header.type[0] = 1; // Ditto
	psvFile->header.slotStartOffset[0] = 0x84; // Ditto
	psvFile->header.dataStartOffset[1] = 0x02; // Ditto
	*(uint32_t*)psvFile->header.saveSize = 0x2000 * blockCount;
	*(uint32_t*)psvFile->header.saveSizeDup = *(uint32_t*)psvFile->header.saveSize;
	*(uint32_t*)psvFile->header.unknown = 0x9003;

	// PS1 filename is important for proper PSV header creation but will not bother safety checking if name was tampered with... user error
	strncpy((char*)psvFile->header.fileName, fileName, sizeof(psvFile->header.fileName));

	// Sign the PSV once we have all of the data set up.
	SignFile(psvFile->header.hash, (uint8_t*)psvFile, cPSVSize, psvFile->header.salt);

	// PSV file name consists of the Game ID (eg. BASLUS-00707) in ASCII + save identifier (eg. SILENT00) in HEX
	// Both of these are stored in header's fileName
	char outputFileName[0x21]; // 12 bytes for Game ID + 8*2 bytes for HEX in ASCII + 5 for ".PSV\0" = 33 bytes (0x21)

	uint8_t i;
	for (i = 0; i < 0xC; ++i) {
		outputFileName[i] = psvFile->header.fileName[i];
	}
	for (uint8_t k = 0; k < 0x8; ++k, ++i) {
		if (psvFile->header.fileName[i] == 0) {
			outputFileName[0xC + k * 2] = 0;
			break;
		}
		else {
			sprintf(&outputFileName[0xC + k * 2], "%02X", psvFile->header.fileName[i]);
		}
	}
	outputFileName[28] = 0;
	strcat(outputFileName, ".PSV");

	// Finally create the PSV file and write the finalized data to it
	FILE* outputFile = fopen(outputFileName, "wb");
	if (!outputFile) {
		printf("Couldn't create PSV file for '%s'! Skipping...\n", fileName);
		free(psvFile);
		return;
	}

	fwrite((uint8_t*)psvFile, cPSVSize, 1, outputFile);
	printf("'%s' created successfully!\n", outputFileName);

	fclose(outputFile);
	free(psvFile);
}

static void ExtractSaveFromPSV(PSVFile_t* psvFile)
{
	if (!psvFile) {
		return;
	}

	char outputFileName[sizeof(psvFile->header.fileName) + 1];
	strncpy(outputFileName, (const char*)psvFile->header.fileName, sizeof(outputFileName));

	FILE* outputFile = fopen(outputFileName, "wb");
	if (!outputFile) {
		printf("Couldn't create '%s' save file! Skipping...\n", outputFileName);
		return;
	}

	const size_t cBlockCount = *(uint32_t*)psvFile->header.saveSize / sizeof(SaveBlock_t);

	fwrite(&psvFile->save, sizeof(SaveBlock_t), cBlockCount, outputFile);
	printf("Extracted '%s' successfully!\n", outputFileName);
	fclose(outputFile);
}

typedef struct {
	uint8_t magic[0x0C]; // VMP stored as "\0PMV\x80"
	uint8_t salt[SALT_SIZE]; // Same as PSV
	uint8_t hash[HASH_SIZE]; // Same as PSV
	uint8_t padding[0x4C]; // Always 0
} VMPHeader_t;

typedef enum {
	FIRST_LINK_OR_ONLY = 0x51, // Blocks that are the beginning of a block chain link or singular save blocks, differentiated by nextBlockNr in DirectoryFrame_t
	MIDDLE_LINK = 0x52, // Intermediary blocks in a chain link
	LAST_LINK = 0x53, //  Last block in a chain link, eg. 0x51 -> 0x52 -> 0x52 -> 0x53
	FREE_BLOCK = 0xA0, // Free blocks ready to accept new saves
	DELETED_FIRST_LINK_OR_ONLY = 0xA1, // Deleted blocks that were start of chain link or singular saves
	DELETED_MIDDLE_LINK = 0xA2, // Deleted intermediary blocks that were part of a chain link
	DELETED_LAST_LINK = 0xA3 // Deleted blocks that were last in a chain link
} BlockAllocationState;

typedef struct {
	uint8_t blockState[0x4]; // Uses one of the BlockAllocationState values, is a 4 bytes array instead of enum to ensure correct frame size and padding
	uint8_t saveSize[0x4]; // Multiple of 0x2000 (8192)
	uint8_t nextBlockNr[0x2]; // 0xFFFF for empty, last (0x53) or only blocks (0x51), otherwise contains index number for next block in chain link (0..14 for Block Nr 1..15)
	uint8_t fileName[0x15]; // Filename in ASCII, 20 bytes max + 0 terminated
	uint8_t unused[0x60]; // 0x00 filled
	uint8_t checksum; // All of the bytes above XOR'd with each other
} DirectoryFrame_t;

typedef struct {
	uint8_t brokenSectorNr[0x4]; // All 0xFF if no broken sector which is the usual scenario for VMP files
	uint8_t unused[0x7B]; // All 0s except for index 4 and 5 having 0xFF
	uint8_t checksum; // All of the bytes above XOR'd with each other, which is gonna be 0 with the defaults above
} BrokenSectorInfo_t;

// For frames that are 0xFF filled
typedef uint8_t UnusedFrame_t[0x80];

typedef struct {
	// Memory Card Header (Block 0, Frame 0)
	uint8_t magic[0x02]; // Always "MC"
	uint8_t unused[0x7D]; // 0x00 filled
	uint8_t checksum; // All of the bytes above XOR'd with each other, pretty much always 4D (M) ^ 43 (C) = 0x0E
	// Directory Frames For Each Block (Block 0, Frames 1..15)
	DirectoryFrame_t directoryFrames[MAX_SAVE_BLOCKS];
	// Broken Sector List (Block 0, Frames 16..35)
	BrokenSectorInfo_t brokenSectorsInfo[0x14];
	// Broken Sector Replacement Data (Block 0, Frames 36..55)
	UnusedFrame_t brokenSectorsData[0x14]; // All 0xFF for no broken sectors
	// Unused Frames (Block 0, Frames 56..62)
	UnusedFrame_t unusedFrames[0x7]; // Also 0xFF filled
	// Write Test Frame (Block 0, Frame 63)
	UnusedFrame_t writeTestFrame; // Can be a copy of "MC" header (Block/Frame 0) but it's all 0s on my cards
	// Save Data Blocks (Block 1..15)
	SaveBlock_t saveBlocks[MAX_SAVE_BLOCKS];
} MemoryCard_t;

typedef struct {
	VMPHeader_t header;
	MemoryCard_t card;
} VMPFile_t;

static inline uint8_t XorBuf(const uint8_t* buffer, size_t bufferLen)
{
	uint8_t xorValue = 0;
	for (size_t i = 0; i < bufferLen; ++i) {
		xorValue ^= buffer[i];
	}
	return xorValue;
}

static void CreateVMPFromSaves(const char* files[], size_t filesCount)
{
	VMPFile_t* vmpFile = (VMPFile_t*)calloc(1, sizeof(VMPFile_t));

	// Fill in necessary VMP header data.
	memcpy(vmpFile->header.magic, "\0PMV\x80", 5);
	memcpy(vmpFile->header.salt, "brkzlrwuzhere", 13); // Create a random key salt as the PSP doesn't care about the specific salt value

	// Fill in necessary MC header data.
	memcpy(vmpFile->card.magic, "MC", 2);
	vmpFile->card.checksum = 0x0E;

	// Fill in unused frames
	memset(vmpFile->card.brokenSectorsInfo[0].brokenSectorNr, 0xFF, 4);
	vmpFile->card.brokenSectorsInfo[0].unused[4] = 0xFF;
	vmpFile->card.brokenSectorsInfo[0].unused[5] = 0xFF;
	for (size_t i = 1; i < 0x14; ++i) {
		memcpy(&vmpFile->card.brokenSectorsInfo[i], &vmpFile->card.brokenSectorsInfo[0], sizeof(BrokenSectorInfo_t));
	}
	memset(vmpFile->card.brokenSectorsData, 0xFF, sizeof(vmpFile->card.brokenSectorsData));
	memset(vmpFile->card.unusedFrames, 0xFF, sizeof(vmpFile->card.unusedFrames));

	// Go through all of the valid PS1 saves and add them into the VMP file
	uint_fast8_t allocatedBlocks = 0;
	for (size_t fileIndex = 0; fileIndex < filesCount; ++fileIndex) {
		if (allocatedBlocks >= MAX_SAVE_BLOCKS) {
			puts("Save blocks limit reached! Ignoring rest of files...");
			break;
		}

		FILE* file = fopen(files[fileIndex], "rb");
		if (!file) {
			printf("Error opening file '%s'! Skipping...\n", files[fileIndex]);
			continue;
		}

		fseek(file, 0, SEEK_END);
		const long cFileSize = ftell(file);
		if (cFileSize == 0 || cFileSize % sizeof(SaveBlock_t) != 0) {
			printf("Input file '%s' is not a valid PS1 save! Skipping...\n", files[fileIndex]);
			fclose(file);
			continue;
		}
		fseek(file, 0, SEEK_SET);

		// Do we have space for however many blocks this save occupies?
		const long cBlockCount = cFileSize / sizeof(SaveBlock_t);
		if (allocatedBlocks + cBlockCount > MAX_SAVE_BLOCKS) {
			printf("'%s' exceeds available VMP save blocks! Skipping...\n", files[fileIndex]);
			continue;
		}

		printf("Processing '%s'\n", files[fileIndex]);
		for (size_t i = allocatedBlocks; i < allocatedBlocks + cBlockCount; ++i) {
			DirectoryFrame_t* directory = &vmpFile->card.directoryFrames[i];

			// First of link or only block has 0x51 state always.
			// Filename and saveSize are also only present on 0x51 blocks.
			if (i == allocatedBlocks) {
				directory->blockState[0] = FIRST_LINK_OR_ONLY;
				if (cBlockCount == 1) {
					*(uint16_t*)directory->nextBlockNr = 0xFFFF;
				}
				else {
					*(uint16_t*)directory->nextBlockNr = i + 1;
				}
				*(uint32_t*)directory->saveSize = 0x2000 * cBlockCount;
				strncpy((char*)directory->fileName, files[fileIndex], sizeof(directory->fileName) - 1);
				directory->fileName[0x14] = 0;
			}
			// Middle block
			else if (i + 1 < allocatedBlocks + cBlockCount) {
				directory->blockState[0] = MIDDLE_LINK;
				*(uint16_t*)directory->nextBlockNr = i + 1;
			}
			// Last block
			else {
				directory->blockState[0] = LAST_LINK;
				*(uint16_t*)directory->nextBlockNr = 0xFFFF;
			}

			directory->checksum = XorBuf((uint8_t*)directory, sizeof(DirectoryFrame_t) - 1);
		}

		fread(&vmpFile->card.saveBlocks[allocatedBlocks], sizeof(SaveBlock_t), cBlockCount, file);
		allocatedBlocks += cBlockCount;

		fclose(file);
	}

	// Set remaining blocks as empty sectors
	for (size_t i = allocatedBlocks; i < MAX_SAVE_BLOCKS; ++i) {
		vmpFile->card.directoryFrames[i].blockState[0] = FREE_BLOCK;
		*(uint16_t*)vmpFile->card.directoryFrames[i].nextBlockNr = 0xFFFF;
		vmpFile->card.directoryFrames[i].checksum = 0xA0;
	}

	// Sign the VMP after we have all of the data set up
	SignFile(vmpFile->header.hash, (uint8_t*)vmpFile, sizeof(VMPFile_t), vmpFile->header.salt);

	// Finally create the VMP file and write the finalized data to it
	FILE* outputFile = fopen("SCEVMC0.VMP", "wb");
	if (!outputFile) {
		puts("Couldn't create VMP file! Aborting...");
		free(vmpFile);
		return;
	}

	fwrite((uint8_t*)vmpFile, sizeof(VMPFile_t), 1, outputFile);
	puts("VMP created successfully!");

	fclose(outputFile);
	free(vmpFile);
}

static void ExtractSavesFromVMP(VMPFile_t* vmpFile)
{
	if (!vmpFile) {
		return;
	}

	// We'll ignore checksum or other checks and assume every directory is a valid one
	// Tbh MC corruption is rare outside of on the actual consoles especially since VMPs in circulation are converted properly
	for (size_t frameIndex = 0; frameIndex < MAX_SAVE_BLOCKS; ++frameIndex) {
		DirectoryFrame_t* directory = &vmpFile->card.directoryFrames[frameIndex];
		switch (directory->blockState[0]) {
		case FREE_BLOCK:
		case MIDDLE_LINK:
		case LAST_LINK:
			// Will ignore 0x52 (middle of link) and 0x53 (last of link) as we'll parse links starting from the 0x51 (start) blocks.
			continue;
		case DELETED_FIRST_LINK_OR_ONLY:
		case DELETED_MIDDLE_LINK:
		case DELETED_LAST_LINK:
			printf("Found deleted save block %zu in VMP, but will ignore it\n", frameIndex + 1);
			continue;
		case FIRST_LINK_OR_ONLY: {
			FILE* outputFile = fopen((const char*)directory->fileName, "wb");
			if (!outputFile) {
				printf("Couldn't create '%s' save file! Skipping...\n", (const char*)directory->fileName);
				continue;
			}

			// Single block save
			if (*(uint16_t*)directory->nextBlockNr == 0xFFFF) {
				if (*(uint32_t*)directory->saveSize != sizeof(SaveBlock_t)) {
					printf("Block %zu for save '%s' is corrupted! Skipping save...\n", frameIndex + 1, (const char*)directory->fileName);
					continue;
				}
				fwrite(&vmpFile->card.saveBlocks[frameIndex], sizeof(SaveBlock_t), 1, outputFile);
			}
			// Multiple blocks save
			else {
				if (*(uint32_t*)directory->saveSize % sizeof(SaveBlock_t) != 0) {
					printf("Block %zu for save '%s' is corrupted! Skipping save...\n", frameIndex + 1, (const char*)directory->fileName);
					continue;
				}
				size_t blockToWrite = frameIndex;
				const size_t cBlockCount = (*(uint32_t*)directory->saveSize / sizeof(SaveBlock_t));
				for (size_t i = 0; i < cBlockCount; ++i) {
					fwrite(&vmpFile->card.saveBlocks[blockToWrite], sizeof(SaveBlock_t), 1, outputFile);

					uint16_t nextBlockIndex = *(uint16_t*)directory->nextBlockNr;
					if (nextBlockIndex >= MAX_SAVE_BLOCKS) {
						// Set back directory ptr to original value from beginning of loop for correct fileName print at the end
						directory = &vmpFile->card.directoryFrames[frameIndex];
						// This'll happen on the last iteration and we don't want an out of bounds access below
						break;
					}
					directory = &vmpFile->card.directoryFrames[nextBlockIndex];
					blockToWrite = nextBlockIndex;
				}
			}

			printf("Extracted '%s' successfully!\n", (const char*)directory->fileName);
			fclose(outputFile);
		}
		}
	}
}

int main(int argc, char** argv)
{
	bool extract = false;
	bool psv = false;
	bool vmp = false;

	// VMP supports max 15 saves, just like a Memory Card
	const char* fileNames[15] = { NULL };
	size_t fileCount = 0;
	for (size_t i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "-e", 2)) {
			extract = true;
		}
		else if (!strncmp(argv[i], "-p", 2)) {
			psv = true;
		}
		else if (!strncmp(argv[i], "-v", 2)) {
			vmp = true;
		}
		else {
			if (fileCount == 15) {
				puts("Can't accept more than 15 files! Quitting...");
				return 1;
			}
			fileNames[fileCount++] = argv[i];
		}
	}

	if ((!extract && !psv && !vmp) || fileCount == 0) {
		printf("Usage: %s {-e <PSV or VMP file> to extract | -p <PS1 save to convert to PSV> | -v <PS1 save to convert to VMP>}\n", argv[0]);
		return 1;
	}
	else if (extract && (psv || vmp)) {
		puts("Extract and convert options are mutually exclusive!");
		return 1;
	}

	if (vmp) {
		puts("Creating VMP file...");
		CreateVMPFromSaves(fileNames, fileCount);
	}

	if (psv || extract) {
		for (size_t i = 0; i < fileCount; ++i) {
			FILE* file = fopen(fileNames[i], "rb");
			if (!file) {
				printf("Error opening file '%s'! Skipping...\n", fileNames[i]);
				continue;
			}

			fseek(file, 0, SEEK_END);
			const long cFileSize = ftell(file);
			if (cFileSize == 0) {
				printf("Input file '%s' is empty! Skipping...\n", fileNames[i]);
				fclose(file);
				continue;
			}
			fseek(file, 0, SEEK_SET);

			if (extract) {
				char fileTypeId[5];
				fread(fileTypeId, 5, 1, file);
				fseek(file, 0, SEEK_SET);

				if (!memcmp(fileTypeId, "\0VSP", 4) && (cFileSize - sizeof(PSVHeader_t)) % sizeof(SaveBlock_t) == 0) {
					printf("Detected '%s' as a PSV file, starting extraction...\n", fileNames[i]);

					PSVFile_t* psvFile = (PSVFile_t*)calloc(1, cFileSize);
					fread(psvFile, cFileSize, 1, file);
					ExtractSaveFromPSV(psvFile);
					free(psvFile);
				}
				else if (!memcmp(fileTypeId, "\0PMV\x80", 5) && cFileSize == sizeof(VMPFile_t)) {
					printf("Detected '%s' as a VMP file, starting extraction...\n", fileNames[i]);

					VMPFile_t* vmpFile = (VMPFile_t*)calloc(1, cFileSize);
					fread(vmpFile, cFileSize, 1, file);
					ExtractSavesFromVMP(vmpFile);
					free(vmpFile);
				}
				else {
					printf("Input file '%s' is not a valid PSV or VMP file! Skipping...\n", fileNames[i]);
					fclose(file);
					continue;
				}
			}
			else if (psv) {
				if (cFileSize % sizeof(SaveBlock_t) != 0) {
					printf("Input file '%s' is not a valid PS1 block save! Skipping...\n", fileNames[i]);
					fclose(file);
					continue;
				}

				printf("Creating PSV file for '%s'...\n", fileNames[i]);
				CreatePSVFromSave(file, fileNames[i], cFileSize / sizeof(SaveBlock_t));
			}

			fclose(file);
		}
	}

	return 0;
}
