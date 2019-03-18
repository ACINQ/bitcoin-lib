package fr.acinq;

/*--------------------------------------------------------------------------
 *  Copyright 2007 Taro L. Saito
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *--------------------------------------------------------------------------*/
//--------------------------------------
// SQLite JDBC Project
//
// SQLite.java
// Since: 2007/05/10
//
// $URL$
// $Author$
//--------------------------------------

import java.io.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Set the system properties, org.sqlite.lib.path, org.sqlite.lib.name,
 * appropriately so that the SQLite JDBC driver can find *.dll, *.jnilib and
 * *.so files, according to the current OS (win, linux, mac).
 * <p/>
 * The library files are automatically extracted from this project's package
 * (JAR).
 * <p/>
 * usage: call {@link #initialize()} before using SQLite JDBC driver.
 *
 * @author leo
 */
public class Secp256k1Loader {

    private static boolean extracted = false;

    /**
     * Loads secp256k1 native library.
     *
     * @return True if secp256k1 native library is successfully loaded; false otherwise.
     */
    public static synchronized boolean initialize() throws Exception {
        // only cleanup before the first extract
        if(!extracted) {
            cleanup();
        }
        loadSecp256k1NativeLibrary();
        return extracted;
    }

    private static File getTempDir() {
        return new File(System.getProperty("fr.acinq.secp256k1.tmpdir", System.getProperty("java.io.tmpdir")));
    }

    /**
     * Deleted old native libraries e.g. on Windows the DLL file is not removed
     * on VM-Exit (bug #80)
     */
    static void cleanup() {
        String tempFolder = getTempDir().getAbsolutePath();
        File dir = new File(tempFolder);

        File[] nativeLibFiles = dir.listFiles(new FilenameFilter() {
            private final String searchPattern = "secp256k1-";
            public boolean accept(File dir, String name) {
                return name.startsWith(searchPattern) && !name.endsWith(".lck");
            }
        });
        if(nativeLibFiles != null) {
            for(File nativeLibFile : nativeLibFiles) {
                File lckFile = new File(nativeLibFile.getAbsolutePath() + ".lck");
                if(!lckFile.exists()) {
                    try {
                        nativeLibFile.delete();
                    }
                    catch(SecurityException e) {
                        System.err.println("Failed to delete old native lib" + e.getMessage());
                    }
                }
            }
        }
    }

    private static boolean contentsEquals(InputStream in1, InputStream in2) throws IOException {
        if(!(in1 instanceof BufferedInputStream)) {
            in1 = new BufferedInputStream(in1);
        }
        if(!(in2 instanceof BufferedInputStream)) {
            in2 = new BufferedInputStream(in2);
        }

        int ch = in1.read();
        while(ch != -1) {
            int ch2 = in2.read();
            if(ch != ch2) {
                return false;
            }
            ch = in1.read();
        }
        int ch2 = in2.read();
        return ch2 == -1;
    }

    /**
     * Extracts and loads the specified library file to the target folder
     *
     * @param libFolderForCurrentOS Library path.
     * @param libraryFileName       Library name.
     * @param targetFolder          Target folder.
     * @return
     */
    private static boolean extractAndLoadLibraryFile(String libFolderForCurrentOS, String libraryFileName,
                                                     String targetFolder) {
        String nativeLibraryFilePath = libFolderForCurrentOS + "/" + libraryFileName;
        // Include architecture name in temporary filename in order to avoid conflicts
        // when multiple JVMs with different architectures running at the same time
        String uuid = UUID.randomUUID().toString();
        String extractedLibFileName = String.format("secp256k1-%s-%s", uuid, libraryFileName);
        String extractedLckFileName = extractedLibFileName + ".lck";

        File extractedLibFile = new File(targetFolder, extractedLibFileName);
        File extractedLckFile = new File(targetFolder, extractedLckFileName);

        try {
            // Extract a native library file into the target directory
            InputStream reader = Secp256k1Loader.class.getResourceAsStream(nativeLibraryFilePath);
            if(!extractedLckFile.exists()) {
                new FileOutputStream(extractedLckFile).close();
            }
            FileOutputStream writer = new FileOutputStream(extractedLibFile);
            try {
                byte[] buffer = new byte[8192];
                int bytesRead = 0;
                while((bytesRead = reader.read(buffer)) != -1) {
                    writer.write(buffer, 0, bytesRead);
                }
            }
            finally {
                // Delete the extracted lib file on JVM exit.
                extractedLibFile.deleteOnExit();
                extractedLckFile.deleteOnExit();


                if(writer != null) {
                    writer.close();
                }
                if(reader != null) {
                    reader.close();
                }
            }

            // Set executable (x) flag to enable Java to load the native library
            extractedLibFile.setReadable(true);
            extractedLibFile.setWritable(true, true);
            extractedLibFile.setExecutable(true);

            // Check whether the contents are properly copied from the resource folder
            {
                InputStream nativeIn = Secp256k1Loader.class.getResourceAsStream(nativeLibraryFilePath);
                InputStream extractedLibIn = new FileInputStream(extractedLibFile);
                try {
                    if(!contentsEquals(nativeIn, extractedLibIn)) {
                        throw new RuntimeException(String.format("Failed to write a native library file at %s", extractedLibFile));
                    }
                }
                finally {
                    if(nativeIn != null) {
                        nativeIn.close();
                    }
                    if(extractedLibIn != null) {
                        extractedLibIn.close();
                    }
                }
            }
            return loadNativeLibrary(targetFolder, extractedLibFileName);
        }
        catch(IOException e) {
            System.err.println(e.getMessage());
            return false;
        }

    }

    /**
     * Loads native library using the given path and name of the library.
     *
     * @param path Path of the native library.
     * @param name Name  of the native library.
     * @return True for successfully loading; false otherwise.
     */
    private static boolean loadNativeLibrary(String path, String name) {
        File libPath = new File(path, name);
        if(libPath.exists()) {

            try {
                System.load(new File(path, name).getAbsolutePath());
                return true;
            }
            catch(UnsatisfiedLinkError e) {
                System.err.println("Failed to load native library:" + name + ". osinfo: " + OSInfo.getNativeLibFolderPathForCurrentOS());
                System.err.println(e);
                return false;
            }

        }
        else {
            return false;
        }
    }

    /**
     * Loads secp256k1 native library using given path and name of the library.
     *
     * @throws
     */
    private static void loadSecp256k1NativeLibrary() throws Exception {
        if(extracted) {
            return;
        }

        // Try loading library from fr.acinq.secp256k1.lib.path library path */
        String secp256k1NativeLibraryPath = System.getProperty("fr.acinq.secp256k1.lib.path");
        String secp256k1NativeLibraryName = System.getProperty("fr.acinq.secp256k1.lib.name");
        if(secp256k1NativeLibraryName == null) {
            secp256k1NativeLibraryName = System.mapLibraryName("secp256k1");
            if(secp256k1NativeLibraryName != null && secp256k1NativeLibraryName.endsWith(".dylib")) {
                secp256k1NativeLibraryName = secp256k1NativeLibraryName.replace(".dylib", ".jnilib");
            }
        }

        if(secp256k1NativeLibraryPath != null) {
            if(loadNativeLibrary(secp256k1NativeLibraryPath, secp256k1NativeLibraryName)) {
                extracted = true;
                return;
            }
        }

        // Load the os-dependent library from the jar file
        String packagePath = Secp256k1Loader.class.getPackage().getName().replaceAll("\\.", "/");
        secp256k1NativeLibraryPath = String.format("/%s/native/%s", packagePath, OSInfo.getNativeLibFolderPathForCurrentOS());
        boolean hasNativeLib = hasResource(secp256k1NativeLibraryPath + "/" + secp256k1NativeLibraryName);


        if(!hasNativeLib) {
            if(OSInfo.getOSName().equals("Mac")) {
                // Fix for openjdk7 for Mac
                String altName = "libsecp256k1.jnilib";
                if(hasResource(secp256k1NativeLibraryPath + "/" + altName)) {
                    secp256k1NativeLibraryName = altName;
                    hasNativeLib = true;
                }
            }
        }

        if(!hasNativeLib) {
            extracted = false;
            throw new Exception(String.format("No native library is found for os.name=%s and os.arch=%s. path=%s", OSInfo.getOSName(), OSInfo.getArchName(), secp256k1NativeLibraryPath));
        }

        // temporary library folder
        String tempFolder = getTempDir().getAbsolutePath();
        // Try extracting the library from jar
        if(extractAndLoadLibraryFile(secp256k1NativeLibraryPath, secp256k1NativeLibraryName, tempFolder)) {
            extracted = true;
            return;
        }

        extracted = false;
        return;
    }

    private static boolean hasResource(String path) {
        return Secp256k1Loader.class.getResource(path) != null;
    }


    @SuppressWarnings("unused")
    private static void getNativeLibraryFolderForTheCurrentOS() {
        String osName = OSInfo.getOSName();
        String archName = OSInfo.getArchName();
    }
}
