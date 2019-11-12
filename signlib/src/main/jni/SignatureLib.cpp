//
// Created by Administrator on 2019-10-23.
//
#include "SignatureLib.h"
#include "MD5.h"
#include <jni.h>
#include <string.h>
#include <android/log.h>
#include <malloc.h>

#define  LOG_TAG    "native-dev"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

void trim(char *str) {
    int len,k,i;
    if (str == NULL)
        return;
    len = strlen(str);
    k = 0;
    for (i=0; i<len; i++){
        if ((str[i] != ' ')&&(str[i] != '\n')) {
            str[k]=str[i];
            k++;
        }
    }
    str[k]='\0';
}

void ByteToHexStr(const char *source, char *dest, int sourceLen) {
    short i;
    char highByte, lowByte;

    for (i = 0; i < sourceLen; i++) {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f;
        highByte += 0x30;

        if (highByte > 0x39) {
            dest[i * 2] = highByte + 0x07;
        } else {
            dest[i * 2] = highByte;
        }

        lowByte += 0x30;
        if (lowByte > 0x39) {
            dest[i * 2 + 1] = lowByte + 0x07;
        } else {
            dest[i * 2 + 1] = lowByte;
        }
    }
}

jstring mergeStr(JNIEnv *env, jstring strFist, jstring strLast) {
    char *mStr = new char[280];
    const char *cStrFist = env->GetStringUTFChars(strFist, 0);
    const char *cStrLast = env->GetStringUTFChars(strLast, 0);
    strcat(mStr, cStrFist);
    strcat(mStr, cStrLast);
    trim(mStr);

    env->ReleaseStringUTFChars(strFist, cStrFist);
    env->DeleteLocalRef(strFist);
    env->ReleaseStringUTFChars(strLast, cStrLast);
    env->DeleteLocalRef(strLast);
    //--free(mStr);

    return (env)->NewStringUTF(mStr);
}

jstring encryptMD5ByAppSign(JNIEnv *env, jobject context, jstring str) {
    jstring sign = loadSignature(env, context);
    char *mStr = new char[280];
    const char *cStrFist = env->GetStringUTFChars(str, 0);
    const char *cStrLast = env->GetStringUTFChars(sign, 0);
    strcat(mStr, cStrFist);
    strcat(mStr, cStrLast);
    trim(mStr);
    MD5 md5 = MD5(mStr);
    std::string md5Result = md5.hexdigest();

    env->ReleaseStringUTFChars(str, cStrFist);
    env->DeleteLocalRef(str);
    env->ReleaseStringUTFChars(sign, cStrLast);
    env->DeleteLocalRef(sign);
    free(mStr);

    return env->NewStringUTF(md5Result.c_str());
}

jstring encryptMD5ToString(JNIEnv *env, jstring str) {
    const char *cStr = env->GetStringUTFChars(str, 0);
    MD5 md5 = MD5(cStr);
    std::string md5Result = md5.hexdigest();

    env->ReleaseStringUTFChars(str, cStr);
    env->DeleteLocalRef(str);

    return env->NewStringUTF(md5Result.c_str());
}

jstring ToMd5(JNIEnv *env, jbyteArray source) {
    // MessageDigest类
    jclass classMessageDigest = env->FindClass("java/security/MessageDigest");
    // MessageDigest.getInstance()静态方法
    jmethodID midGetInstance = env->GetStaticMethodID(classMessageDigest, "getInstance",
                                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    // MessageDigest object
    jobject objMessageDigest = env->CallStaticObjectMethod(classMessageDigest, midGetInstance,
                                                           env->NewStringUTF("md5"));

    // update方法，这个函数的返回值是void，写V
    jmethodID midUpdate = env->GetMethodID(classMessageDigest, "update", "([B)V");
    env->CallVoidMethod(objMessageDigest, midUpdate, source);

    // digest方法
    jmethodID midDigest = env->GetMethodID(classMessageDigest, "digest", "()[B");
    jbyteArray objArraySign = (jbyteArray) env->CallObjectMethod(objMessageDigest, midDigest);

    jsize intArrayLength = env->GetArrayLength(objArraySign);
    jbyte *byte_array_elements = env->GetByteArrayElements(objArraySign, NULL);
    size_t length = (size_t) intArrayLength * 2 + 1;
    char *char_result = (char *) malloc(length);
    memset(char_result, 0, length);

    // 将byte数组转换成16进制字符串，发现这里不用强转，jbyte和unsigned char应该字节数是一样的
    ByteToHexStr((const char *) byte_array_elements, char_result, intArrayLength);
    // 在末尾补\0
    *(char_result + intArrayLength * 2) = '\0';

    jstring stringResult = env->NewStringUTF(char_result);
    // release
    env->ReleaseByteArrayElements(objArraySign, byte_array_elements, JNI_ABORT);
    // 释放指针使用free
    free(char_result);
    env->DeleteLocalRef(classMessageDigest);
    env->DeleteLocalRef(objMessageDigest);

    return stringResult;
}

jstring loadSignature(JNIEnv *env, jobject context){
    // 获得Context类
    jclass cls = env->GetObjectClass(context);
    // 得到getPackageManager方法的ID
    jmethodID mid = env->GetMethodID(cls, "getPackageManager",
                                     "()Landroid/content/pm/PackageManager;");

    // 获得应用包的管理器
    jobject pm = env->CallObjectMethod(context, mid);

    // 得到getPackageName方法的ID
    mid = env->GetMethodID(cls, "getPackageName", "()Ljava/lang/String;");
    // 获得当前应用包名
    jstring packageName = (jstring) env->CallObjectMethod(context, mid);

    // 获得PackageManager类
    cls = env->GetObjectClass(pm);
    // 得到getPackageInfo方法的ID
    mid = env->GetMethodID(cls, "getPackageInfo",
                           "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 获得应用包的信息
    jobject packageInfo = env->CallObjectMethod(pm, mid, packageName, 0x40); //GET_SIGNATURES = 64;
    // 获得PackageInfo 类
    cls = env->GetObjectClass(packageInfo);
    // 获得签名数组属性的ID
    jfieldID fid = env->GetFieldID(cls, "signatures", "[Landroid/content/pm/Signature;");
    // 得到签名数组
    jobjectArray signatures = (jobjectArray) env->GetObjectField(packageInfo, fid);
    // 得到签名
    jobject signature = env->GetObjectArrayElement(signatures, 0);

    // 获得Signature类
    cls = env->GetObjectClass(signature);
    // 得到toCharsString方法的ID
    mid = env->GetMethodID(cls, "toByteArray", "()[B");
    // 返回当前应用签名信息
    jbyteArray signatureByteArray = (jbyteArray) env->CallObjectMethod(signature, mid);

    env->DeleteLocalRef(cls);
    env->DeleteLocalRef(pm);
    env->DeleteLocalRef(packageName);
    env->DeleteLocalRef(packageInfo);
    env->DeleteLocalRef(signatures);
    env->DeleteLocalRef(signature);

    return ToMd5(env, signatureByteArray);
}



