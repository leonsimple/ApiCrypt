package com.pingan.apicrypt;

/**
 * Created by kangwei on 2017-8-14.
 */

public class ApiCrypt {
    static {
        System.loadLibrary("api_crypt");
    }

    public static native  String decrypt(String dec);

    public static native  String encrypt(String enc);

}
