/*
 * Copyright (c) 1997, 2007, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

#include <assert.h>
#include "java_lang_ProcessImpl.h"

#include "jni.h"
#include "jvm.h"
#include "jni_util.h"
#include "io_util.h"
#include <windows.h>
#include <io.h>

#define PIPE_SIZE 4096

char *
extractExecutablePath(JNIEnv *env, char *source)
{
    char *p, *r;

    /* If no spaces, then use entire thing */
    if ((p = strchr(source, ' ')) == NULL)
        return source;

    /* If no quotes, or quotes after space, return up to space */
    if (((r = strchr(source, '"')) == NULL) || (r > p)) {
        *p = 0;
        return source;
    }

    /* Quotes before space, return up to space after next quotes */
    p = strchr(r, '"');
    if ((p = strchr(p, ' ')) == NULL)
        return source;
    *p = 0;
    return source;
}

DWORD
selectProcessFlag(JNIEnv *env, jstring cmd0)
{
    char buf[MAX_PATH];
    DWORD newFlag = 0;
    char *exe, *p, *name;
    unsigned char buffer[2];
    long headerLoc = 0;
    int fd = 0;

    exe = (char *)JNU_GetStringPlatformChars(env, cmd0, 0);
    exe = extractExecutablePath(env, exe);

    if (exe != NULL) {
        if ((p = strchr(exe, '\\')) == NULL) {
            SearchPath(NULL, exe, ".exe", MAX_PATH, buf, &name);
        } else {
            p = strrchr(exe, '\\');
            *p = 0;
            p++;
            SearchPath(exe, p, ".exe", MAX_PATH, buf, &name);
        }
    }

    fd = _open(buf, _O_RDONLY);
    if (fd > 0) {
        _read(fd, buffer, 2);
        if (buffer[0] == 'M' && buffer[1] == 'Z') {
            _lseek(fd, 60L, SEEK_SET);
            _read(fd, buffer, 2);
            headerLoc = (long)buffer[1] << 8 | (long)buffer[0];
            _lseek(fd, headerLoc, SEEK_SET);
            _read(fd, buffer, 2);
            if (buffer[0] == 'P' && buffer[1] == 'E') {
                newFlag = DETACHED_PROCESS;
            }
        }
        _close(fd);
    }
    JNU_ReleaseStringPlatformChars(env, cmd0, exe);
    return newFlag;
}

/* We have THREE locales in action:
 * 1. Thread default locale - dictates UNICODE-to-8bit conversion
 * 2. System locale that defines the message localization
 * 3. The file name locale
 * Each locale could be an extended locale, that means that text cannot be
 * mapped to 8bit sequence without multibyte encoding.
 * VM is ready for that, if text is UTF-8.
 * Here we make the work right from the beginning.
 */
size_t os_error_message(int errnum, WCHAR* utf16_OSErrorMsg, size_t maxMsgLength) {
    size_t n = (size_t)FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            (DWORD)errnum,
            0,
            utf16_OSErrorMsg,
            (DWORD)maxMsgLength,
            NULL);
    if (n > 3) {
        // Drop final '.', CR, LF
        if (utf16_OSErrorMsg[n - 1] == L'\n') --n;
        if (utf16_OSErrorMsg[n - 1] == L'\r') --n;
        if (utf16_OSErrorMsg[n - 1] == L'.') --n;
        utf16_OSErrorMsg[n] = L'\0';
    }
    return n;
}

#define MESSAGE_LENGTH (256 + 100)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*x))

static void
win32Error(JNIEnv *env, const WCHAR *functionName)
{
    WCHAR utf16_OSErrorMsg[MESSAGE_LENGTH - 100];
    WCHAR utf16_javaMessage[MESSAGE_LENGTH];
    /*Good suggestion about 2-bytes-per-symbol in localized error reports*/
    char  utf8_javaMessage[MESSAGE_LENGTH*2];
    const int errnum = (int)GetLastError();
    int n = os_error_message(errnum, utf16_OSErrorMsg, ARRAY_SIZE(utf16_OSErrorMsg));
    n = (n > 0)
        ? swprintf(utf16_javaMessage, MESSAGE_LENGTH, L"%s error=%d, %s", functionName, errnum, utf16_OSErrorMsg)
        : swprintf(utf16_javaMessage, MESSAGE_LENGTH, L"%s failed, error=%d", functionName, errnum);

    if (n > 0) /*terminate '\0' is not a part of conversion procedure*/
        n = WideCharToMultiByte(
            CP_UTF8,
            0,
            utf16_javaMessage,
            n, /*by creation n <= MESSAGE_LENGTH*/
            utf8_javaMessage,
            MESSAGE_LENGTH*2,
            NULL,
            NULL);

    /*no way to die*/
    {
        const char *errorMessage = "Secondary error while OS message extraction";
        if (n > 0) {
            utf8_javaMessage[min(MESSAGE_LENGTH*2 - 1, n)] = '\0';
            errorMessage = utf8_javaMessage;
        }
        JNU_ThrowIOException(env, errorMessage);
    }
}

static void
closeSafely(HANDLE handle)
{
    if (handle)
        CloseHandle(handle);
}

JNIEXPORT jlong JNICALL
Java_java_lang_ProcessImpl_create(JNIEnv *env, jclass ignored,
                                  jstring cmd,
                                  jstring envBlock,
                                  jstring dir,
                                  jboolean redirectErrorStream,
                                  jobject in_fd,
                                  jobject out_fd,
                                  jobject err_fd)
{
    HANDLE inRead   = 0;
    HANDLE inWrite  = 0;
    HANDLE outRead  = 0;
    HANDLE outWrite = 0;
    HANDLE errRead  = 0;
    HANDLE errWrite = 0;
    SECURITY_ATTRIBUTES sa;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    const jchar*  pcmd = NULL;
    const jchar*  pdir = NULL;
    const jchar*  penvBlock = NULL;
    jlong ret = 0;
    OSVERSIONINFO ver;
    jboolean onNT = JNI_FALSE;
    DWORD processFlag;

    ver.dwOSVersionInfoSize = sizeof(ver);
    GetVersionEx(&ver);
    if (ver.dwPlatformId == VER_PLATFORM_WIN32_NT)
        onNT = JNI_TRUE;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = 0;
    sa.bInheritHandle = TRUE;

    if (!(CreatePipe(&inRead,  &inWrite,  &sa, PIPE_SIZE) &&
          CreatePipe(&outRead, &outWrite, &sa, PIPE_SIZE) &&
          CreatePipe(&errRead, &errWrite, &sa, PIPE_SIZE))) {
        win32Error(env, L"CreatePipe");
        goto Catch;
    }

    assert(cmd != NULL);
    pcmd = (*env)->GetStringChars(env, cmd, NULL);
    if (pcmd == NULL) goto Catch;

    if (dir != 0) {
        pdir = (*env)->GetStringChars(env, dir, NULL);
        if (pdir == NULL) goto Catch;
    }
    if (envBlock != NULL) {
        penvBlock = ((*env)->GetStringChars(env, envBlock, NULL));
        if (penvBlock == NULL) goto Catch;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = inRead;
    si.hStdOutput = outWrite;
    si.hStdError  = redirectErrorStream ? outWrite : errWrite;

    SetHandleInformation(inWrite, HANDLE_FLAG_INHERIT, FALSE);
    SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, FALSE);
    SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, FALSE);

    if (redirectErrorStream)
        SetHandleInformation(errWrite, HANDLE_FLAG_INHERIT, FALSE);

    if (onNT)
        processFlag = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    else
        processFlag = selectProcessFlag(env, cmd) | CREATE_UNICODE_ENVIRONMENT;
    ret = CreateProcessW(0,                /* executable name */
                         (LPWSTR)pcmd,     /* command line */
                         0,                /* process security attribute */
                         0,                /* thread security attribute */
                         TRUE,             /* inherits system handles */
                         processFlag,      /* selected based on exe type */
                         (LPVOID)penvBlock,/* environment block */
                         (LPCWSTR)pdir,    /* change to the new current directory */
                         &si,              /* (in)  startup information */
                         &pi);             /* (out) process information */
    if (!ret) {
        win32Error(env, L"CreateProcess");
        goto Catch;
    }

    CloseHandle(pi.hThread);
    ret = (jlong)pi.hProcess;
    (*env)->SetLongField(env, in_fd,  IO_handle_fdID, (jlong)inWrite);
    (*env)->SetLongField(env, out_fd, IO_handle_fdID, (jlong)outRead);
    (*env)->SetLongField(env, err_fd, IO_handle_fdID, (jlong)errRead);

 Finally:
    /* Always clean up the child's side of the pipes */
    closeSafely(inRead);
    closeSafely(outWrite);
    closeSafely(errWrite);

    if (pcmd != NULL)
        (*env)->ReleaseStringChars(env, cmd, pcmd);
    if (pdir != NULL)
        (*env)->ReleaseStringChars(env, dir, pdir);
    if (penvBlock != NULL)
        (*env)->ReleaseStringChars(env, envBlock, penvBlock);
    return ret;

 Catch:
    /* Clean up the parent's side of the pipes in case of failure only */
    closeSafely(inWrite);
    closeSafely(outRead);
    closeSafely(errRead);
    goto Finally;
}

JNIEXPORT jint JNICALL
Java_java_lang_ProcessImpl_getExitCodeProcess(JNIEnv *env, jclass ignored, jlong handle)
{
    DWORD exit_code;
    if (GetExitCodeProcess((HANDLE) handle, &exit_code) == 0)
        win32Error(env, L"GetExitCodeProcess");
    return exit_code;
}

JNIEXPORT jint JNICALL
Java_java_lang_ProcessImpl_getStillActive(JNIEnv *env, jclass ignored)
{
    return STILL_ACTIVE;
}

JNIEXPORT void JNICALL
Java_java_lang_ProcessImpl_waitForInterruptibly(JNIEnv *env, jclass ignored, jlong handle)
{
    HANDLE events[2];
    events[0] = (HANDLE) handle;
    events[1] = JVM_GetThreadInterruptEvent();

    if (WaitForMultipleObjects(sizeof(events)/sizeof(events[0]), events,
                               FALSE,    /* Wait for ANY event */
                               INFINITE) /* Wait forever */
        == WAIT_FAILED)
        win32Error(env, L"WaitForMultipleObjects");
}

JNIEXPORT void JNICALL
Java_java_lang_ProcessImpl_terminateProcess(JNIEnv *env, jclass ignored, jlong handle)
{
    TerminateProcess((HANDLE) handle, 1);
}

JNIEXPORT jboolean JNICALL
Java_java_lang_ProcessImpl_closeHandle(JNIEnv *env, jclass ignored, jlong handle)
{
    return CloseHandle((HANDLE) handle);
}
