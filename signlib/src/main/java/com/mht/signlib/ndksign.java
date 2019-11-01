package com.mht.signlib;

public class ndksign {

    static {
        System.loadLibrary("mhtndksignLib");
    }

    /*
     * 获取当前SO版本
     */
    public static native String getVersion();

    /*
     * 获取APP签名数据
     */
    public static native String getAppSignature(Object context);

    /*
     * 根据APP签名数据对字符str进行MD5
     */
    public static native String getEncryptMD5ByAppSign(Object context, String str);

    /*
     * 直接MD5 C++实现
     */
    public static native String getEncryptMD5ToString(String str);
}
