# SaveConverter
This is a small program that I made for converting PS1 saves to PS3 (PSV) / PSP (VMP) format and vice versa.

There are a lot of utilities out there, in both program and web format, that already do the same thing and in a better way for sure but I made this to fit my specific workflow to make archiving my PS1 saves easier and faster, especially when dealing with a huge bulk of saves at a time.

## How To Use
The program accepts up to 15 files (which is the limit of saves for a PS1 memory card) and additionally 3 command line options:
- **Extraction `-e`**: In this mode, the program will automatically detect if the files are of type VMP or PSV and then extract the embedded PS1 saves.
  - You can combine both VMP and PSV files in this list of files. The program will extract from both types at the same time.
  - Multi-block saves are also supported and will be extracted correctly.
- **PSV `-p`**: In this mode, the program will convert the supplied PS1 saves into their respective PSV files.
  - The PSV files will be signed and work on any PS3, including OFWs.
- **VMP `-v`**: In this mode, the program will convert the supplied PS1 saves into a single VMP file.
  - The VMP file will be signed and work on any PSP, including OFWs.
  - Maybe in the future I might remove the 15 file limit and any excess file over 15 will go into additional VMP files.

### Notes
- ***You can combine both `-p -v` options to convert all of the PS1 saves into their respective PSV files + a single VMP file containing all the supplied saves.***
- ***Extraction and PSV/VMP modes are mutually exclusive. Use one or the other on a single execution.***
