//
// Created by Administrator on 2019-11-1.
//
#include "com_mht_signlib_ndksign.h"
#include "mhtndksignLib.h"
#include "SignatureLib.h"

JNIEXPORT jstring JNICALL Java_com_mht_signlib_ndksign_getVersion
  (JNIEnv *env, jclass obj){
      return env->NewStringUTF("1.0");
  }

JNIEXPORT jstring JNICALL Java_com_mht_signlib_ndksign_getAppSignature
  (JNIEnv *env, jclass obj, jobject content) {
      return loadSignature(env, content);
  }

JNIEXPORT jstring JNICALL Java_com_mht_signlib_ndksign_getEncryptMD5ByAppSign
  (JNIEnv *env, jclass obj, jobject content, jstring str) {
      return encryptMD5ByAppSign(env, content, str);
  }

JNIEXPORT jstring JNICALL Java_com_mht_signlib_ndksign_getEncryptMD5ToString
  (JNIEnv *env, jclass obj, jstring str) {
      return encryptMD5ToString(env, str);
  }