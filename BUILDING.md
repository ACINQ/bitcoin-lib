# Build instructions

## Building JNI bindings for libsecp256k1

### For Linux 64 bits

We build on Ubuntu 18.10 64 bits, you'll have to adapt this procedure to other distributions.

Set JAVA_HOME to point to your JDK.
Install build tools:

```
$ sudo apt install build-essential autotools-dev libtool automake
```

Build the native library:

```
$ cd secp256k1
$ ./autogen.sh
$./configure --enable-experimental --enable-module_ecdh --enable-jni && make clean && make CFLAGS="-std=c99"                                 
$ cp ./.libs/libsecp256k1.so ../src/main/resources/fr/acinq/native/Linux/x86_64/
```

### For windows 64 bits

Windows bindings are cross-built on Linux. You need to install the mingw toolchain and have JAVA_HOME point to a Windows JDK
                      
```
$ sudo apt install g++-mingw-w64-x86-64
$ sudo update-alternatives --config x86_64-w64-mingw32-g++ # Set the default mingw32 g++ compiler option to posix.                        
```

Build the native library:

```
# this is needed to compile shared libraries, otherwise you'll get:
# libtool: warning: undefined symbols not allowed in x86_64-w64-mingw32 shared libraries; building static only                              
$ echo "LDFLAGS = -no-undefined" >> Makefile.am
$ ./configure --host=x86_64-w64-mingw32 --enable-experimental --enable-module_ecdh --enable-jni && make clean && make CFLAGS="-std=c99"
cp ./.libs/libsecp256k1-0.dll ../src/main/resources/fr/acinq/native/Windows/x86_64/secp256k1.dll                                            
```

### For Osx 64 bits

Osx bindings are built on Osx. You need to install Xcode, Homebrew, and build tools:

```
$ brew install automake libtool
$./configure --enable-experimental --enable-module_ecdh --enable-jni && make clean && make CFLAGS="-std=c99"                                 
$ cp ./.libs/libsecp256k1.dylib ../src/main/resources/fr/acinq/native/Mac/x86_64/libsecp256k1.jnilib
```

## Building the Scala library

To build bitcoin-lib, you need:
 - a JDK, we recommend using OpenJDK 11
 - Maven 3.5.4 or newer
 
 The use maven to build the library:
 ```
 $ mvn install
 ```
