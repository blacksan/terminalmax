// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors
//
// JNI glue for org.terminalmax.core.wireguard.WgBridgeNative. Compiled by
// cgo as part of package main, only for GOOS=android (file name suffix).
// It calls the exported Go functions directly, like wireguard-android's
// libwg-go does.

#ifdef __ANDROID__

#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

extern int wgbStart(char *confText, char *errBuf, int errLen);
extern int wgbOpenForward(int handle, char *target, unsigned char *tokenOut, char *errBuf, int errLen);
extern int wgbStats(int handle, char *buf, int len, char *errBuf, int errLen);
extern int wgbRebind(int handle);
extern void wgbStop(int handle);
extern int wgbLastError(char *buf, int len);

#define ERR_LEN 512
#define STATS_LEN 768 /* > wgconf.MaxJSONLen */
#define TOKEN_LEN 32

/* memset the compiler may not optimise away. */
static void *(*volatile secure_memset)(void *, int, size_t) = memset;
static void wipe(void *p, size_t n)
{
	if (p != NULL && n > 0)
		secure_memset(p, 0, n);
}

/* Throws java.io.IOException(msg); msg must be printable ASCII. Returns
 * immediately (with an exception pending) if the class cannot be found. */
static void throw_io(JNIEnv *env, const char *msg)
{
	jclass cls = (*env)->FindClass(env, "java/io/IOException");
	if (cls == NULL)
		return; /* NoClassDefFoundError already pending */
	(*env)->ThrowNew(env, cls, msg);
	(*env)->DeleteLocalRef(env, cls);
}

static void throw_io_err(JNIEnv *env, const char *err, const char *fallback)
{
	throw_io(env, (err != NULL && err[0] != '\0') ? err : fallback);
}

JNIEXPORT jint JNICALL
Java_org_terminalmax_core_wireguard_WgBridgeNative_nativeStart(JNIEnv *env, jobject thiz, jbyteArray conf)
{
	(void)thiz;
	if (conf == NULL) {
		throw_io(env, "wgbridge: config is null");
		return -6;
	}
	jsize len = (*env)->GetArrayLength(env, conf);
	if (len < 0) {
		throw_io(env, "wgbridge: invalid config length");
		return -6;
	}
	/* Copy with GetByteArrayRegion (not GetByteArrayElements, whose copy the
	 * VM may keep or not wipe); the only native copy is buf, wiped below.
	 * The caller owns zeroing its ByteArray. */
	char *buf = malloc((size_t)len + 1);
	if (buf == NULL) {
		throw_io_err(env, "", "wgbridge: out of memory");
		return -6;
	}
	(*env)->GetByteArrayRegion(env, conf, 0, len, (jbyte *)buf);
	if ((*env)->ExceptionCheck(env)) {
		wipe(buf, (size_t)len);
		free(buf);
		return -6;
	}
	buf[len] = '\0';
	char err[ERR_LEN];
	err[0] = '\0';
	/* Go parses the text in place and retains no part of it. */
	int ret = wgbStart(buf, err, ERR_LEN);
	wipe(buf, (size_t)len + 1);
	free(buf);
	if (ret < 0)
		throw_io_err(env, err, "wgbridge: start failed");
	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_terminalmax_core_wireguard_WgBridgeNative_nativeLastError(JNIEnv *env, jobject thiz)
{
	(void)thiz;
	char err[ERR_LEN];
	err[0] = '\0';
	wgbLastError(err, ERR_LEN);
	return (*env)->NewStringUTF(env, err);
}

JNIEXPORT jint JNICALL
Java_org_terminalmax_core_wireguard_WgBridgeNative_nativeOpenForward(JNIEnv *env, jobject thiz, jint handle, jstring target, jbyteArray tokenOut)
{
	(void)thiz;
	if (target == NULL || tokenOut == NULL)
		return -6;
	if ((*env)->GetArrayLength(env, tokenOut) != TOKEN_LEN) {
		throw_io(env, "wgbridge: token buffer must be 32 bytes");
		return -6;
	}
	const char *t = (*env)->GetStringUTFChars(env, target, NULL);
	if (t == NULL)
		return -6; /* OutOfMemoryError already pending */
	unsigned char tok[TOKEN_LEN];
	char err[ERR_LEN];
	memset(tok, 0, sizeof(tok));
	err[0] = '\0';
	int ret = wgbOpenForward(handle, (char *)t, tok, err, ERR_LEN);
	(*env)->ReleaseStringUTFChars(env, target, t);
	if (ret < 0) {
		wipe(tok, sizeof(tok));
		throw_io_err(env, err, "wgbridge: open forward failed");
		return ret;
	}
	(*env)->SetByteArrayRegion(env, tokenOut, 0, TOKEN_LEN, (const jbyte *)tok);
	wipe(tok, sizeof(tok));
	return ret; /* if SetByteArrayRegion threw, the exception is pending */
}

JNIEXPORT jstring JNICALL
Java_org_terminalmax_core_wireguard_WgBridgeNative_nativeStats(JNIEnv *env, jobject thiz, jint handle)
{
	(void)thiz;
	char buf[STATS_LEN];
	char err[ERR_LEN];
	buf[0] = '\0';
	err[0] = '\0';
	int n = wgbStats(handle, buf, (int)sizeof(buf), err, ERR_LEN);
	if (n < 0) {
		throw_io_err(env, err, "wgbridge: stats failed");
		return NULL;
	}
	return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL
Java_org_terminalmax_core_wireguard_WgBridgeNative_nativeRebind(JNIEnv *env, jobject thiz, jint handle)
{
	(void)env;
	(void)thiz;
	return wgbRebind(handle);
}

JNIEXPORT void JNICALL
Java_org_terminalmax_core_wireguard_WgBridgeNative_nativeStop(JNIEnv *env, jobject thiz, jint handle)
{
	(void)env;
	(void)thiz;
	wgbStop(handle);
}

#endif /* __ANDROID__ */
