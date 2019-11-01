//
// Created by Administrator on 2019-11-1.
//

#include <jni.h>
#ifndef NATIVESIGN_SIGNATURELIB_H
#define NATIVESIGN_SIGNATURELIB_H

#ifdef __cplusplus
extern "C"{
#endif

jstring loadSignature(JNIEnv *, jobject);
jstring encryptMD5ByAppSign(JNIEnv *, jobject, jstring);
jstring encryptMD5ToString(JNIEnv *, jstring);
jstring mergeStr(JNIEnv *, jstring, jstring);

#ifdef __cplusplus
}
#endif

#endif //NATIVESIGN_SIGNATURELIB_H
