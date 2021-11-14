package com.huawei;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * AES CBC PKCS5 模式加密解密
 */
public class AesUtils {

    private static final String CHARSET = "UTF-8";

    /**
     * 加密
     * @param content
     * @param key
     * @param iv
     * @return
     * @throws Exception
     */
    public static String encrypt(String content, String key, String iv)
            throws Exception {

        //明文
        byte[] contentBytes = content.getBytes(CHARSET);

        //AES KEY
        byte[] keyBytes = key.getBytes(CHARSET);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        //AES IV
        byte[] initParam = iv.getBytes(CHARSET);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        byte[] byEnd = cipher.doFinal(contentBytes);

        //加密后的byte数组转BASE64字符串
        String strEnd = java.util.Base64.getEncoder().encodeToString(byEnd);
        return strEnd;
    }

    /**
     * 解密
     * @param content
     * @param key
     * @param iv
     * @return
     * @throws Exception
     */
    public static String decrypt(String content, String key, String iv)
            throws Exception {
        //反向解析BASE64字符串为byte数组
        byte[] encryptedBytes = java.util.Base64.getDecoder().decode(content);

        //AES KEY
        byte[] keyBytes = key.getBytes(CHARSET);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        //AES IV
        byte[] initParam = iv.getBytes(CHARSET);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        byte[] byEnd = cipher.doFinal(encryptedBytes);

        //加密后的byte数组直接转字符串
        String strEnd = new String(byEnd, CHARSET);
        return strEnd;
    }

}


class GcmEncryptor {
    Key key;
  
    GcmEncryptor(byte[] key) {
      if (key.length != 32) throw new IllegalArgumentException();
      this.key = new SecretKeySpec(key, "AES");
    }
  
    // the output is sent to users
    byte[] encrypt(byte[] src) throws Exception {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] iv = cipher.getIV(); // See question #1
      assert iv.length == 12; // See question #2
      byte[] cipherText = cipher.doFinal(src);
      assert cipherText.length == src.length + 16; // See question #3
      byte[] message = new byte[12 + src.length + 16]; // See question #4
      System.arraycopy(iv, 0, message, 0, 12);
      System.arraycopy(cipherText, 0, message, 12, cipherText.length);
      return message;
    }
  
    // the input comes from users
    byte[] decrypt(byte[] message) throws Exception {
      if (message.length < 12 + 16) throw new IllegalArgumentException();
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec params = new GCMParameterSpec(128, message, 0, 12);
      cipher.init(Cipher.DECRYPT_MODE, key, params);
      return cipher.doFinal(message, 12, message.length - 12);
    }
  }