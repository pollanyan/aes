package com.huawei;

public class App {

    private static final String IV_STRING = "abcdefghABCDEFGH";

    public static void main(String[] args) {

        try {

            String cc = "中华 HELLO~！@#￥%……&*（）——+1";
            System.out.printf("明文：%s\n", cc);

            String aesKey = "12345678901234567890123456789012";
            String aa = AesUtils.encrypt(cc, aesKey, IV_STRING);
            System.out.printf("密文(AES256) ：%s\n", aa);

            String dd = AesUtils.decrypt(aa, aesKey, IV_STRING);
            System.out.printf("解密后明文：%s\n", dd);

        } catch (Exception ex) {
            System.out.println("ex：\r\n" + ex.getMessage());
        }
    }
}