@echo off
echo Building zsign...

REM Create temp directory for building
mkdir build_temp
cd build_temp

REM Clone required repositories
git clone https://github.com/witwall/mman-win32.git
git clone https://github.com/openssl/openssl.git
git clone https://github.com/zhlynn/zsign.git

REM Build mman-win32
cd mman-win32
./configure --cross-prefix=x86_64-w64-mingw32-
make

REM Build openssl
cd ../openssl
git checkout OpenSSL_1_0_2s
./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64
make

REM Build zsign
cd ../zsign
x86_64-w64-mingw32-g++ *.cpp common/*.cpp -o zsign.exe -lcrypto -I../mman-win32 -std=c++11 -I../openssl/include/ -DWINDOWS -L../openssl -L../mman-win32 -lmman -lgdi32 -m64 -static -static-libgcc -lws2_32

REM Copy the resulting zsign.exe
copy zsign.exe ..\..\zsign.exe

REM Clean up
cd ..
cd ..
rmdir /s /q build_temp

echo Build complete!
