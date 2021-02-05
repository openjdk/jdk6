/*
 * Copyright (c) 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package jdk.testlibrary;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


/**
 * Common library for various test file utility functions.
 */
public final class FileUtils {

    private static final boolean isWindows =
                            System.getProperty("os.name").startsWith("Windows");
    private static final int RETRY_DELETE_MILLIS = isWindows ? 500 : 0;
    private static final int MAX_RETRY_DELETE_TIMES = isWindows ? 15 : 0;

    /**
     * Deletes a file, retrying if necessary.
     *
     * @param path  the file to delete
     *
     * @throws NoSuchFileException
     *         if the file does not exist (optional specific exception)
     * @throws DirectoryNotEmptyException
     *         if the file is a directory and could not otherwise be deleted
     *         because the directory is not empty (optional specific exception)
     * @throws IOException
     *         if an I/O error occurs
     */
    public static void deleteFileWithRetry(File path)
        throws IOException
    {
        try {
            deleteFileWithRetry0(path);
        } catch (InterruptedException x) {
            throw new IOException("Interrupted while deleting.", x);
        }
    }

    /**
     * Deletes a file, retrying if necessary.
     * No exception thrown if file doesn't exist.
     *
     * @param path  the file to delete
     *
     * @throws NoSuchFileException
     *         if the file does not exist (optional specific exception)
     * @throws DirectoryNotEmptyException
     *         if the file is a directory and could not otherwise be deleted
     *         because the directory is not empty (optional specific exception)
     * @throws IOException
     *         if an I/O error occurs
     */
    public static void deleteFileIfExistsWithRetry(File path)
        throws IOException
    {
        try {
            if (path.exists())
                deleteFileWithRetry0(path);
        } catch (InterruptedException x) {
            throw new IOException("Interrupted while deleting.", x);
        }
    }

    private static void deleteFileWithRetry0(File path)
        throws IOException, InterruptedException
    {
        int times = 0;
        boolean result = path.delete();
        while (!result) {
            times++;
            if (times > MAX_RETRY_DELETE_TIMES)
                throw new IOException("File still exists after " + times + " waits.");
            Thread.sleep(RETRY_DELETE_MILLIS);
            result = path.delete();
        }
    }

    /**
     * Deletes a directory and its subdirectories, retrying if necessary.
     *
     * @param dir  the directory to delete
     *
     * @throws  IOException
     *          If an I/O error occurs. Any such exceptions are caught
     *          internally. If only one is caught, then it is re-thrown.
     *          If more than one exception is caught, then the second and
     *          following exceptions are added as suppressed exceptions of the
     *          first one caught, which is then re-thrown.
     */
    public static void deleteFileTreeWithRetry(File dir)
         throws IOException
    {
        boolean failed = false;
        final List<Boolean> results = deleteFileTreeUnchecked(dir);
        failed = !results.isEmpty();
        if (failed)
            throw new IOException();
    }

    public static List<Boolean> deleteFileTreeUnchecked(File dir) {
        final List<Boolean> results = new ArrayList<Boolean>();
        for (File file : dir.listFiles()) {
            if (file.isDirectory()) {
                results.addAll(deleteFileTreeUnchecked(file));
            } else {
                results.add(file.delete());
            }
        }
        return results;
    }
}
