# PS1Utils
This is a collection of PS1 related utilities I made for my own needs and workflow.

I doubt this might be of use to anybody as there are better tools out there but just in case you're interested, check out the individual project folders for their own READMEs.

Feel free to get inspired from the code or use parts of it.

## Compiling
At the root of this repo, run the following:
```sh
cmake -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build
```
You can then find the binaries in the `bin` folder.

## Install
Optionally you can also install these (by default to `/usr/local/bin`)
```sh
cd build
sudo make install
```
