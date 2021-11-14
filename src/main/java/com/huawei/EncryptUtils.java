package com.huawei;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public enum EncryptUtils {

    /**
     * 单例
     */
    SINGLETON;

    private static final int AES_BLOCK_SIZE = 128;
    private SecretKeySpec secretKeySpec;

    public SecretKeySpec generateKey() {

        try {
            KeyGenerator keyGenerator;
            keyGenerator = KeyGenerator.getInstance("AES");
            // 初始化密钥生成器，指定密钥长度为128，指定随机源的种子为指定的密钥
            keyGenerator.init(AES_BLOCK_SIZE);
            SecretKey secretKey = keyGenerator.generateKey();
            this.secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

            return secretKeySpec;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();

            return null;
        }
    }

    public String wrap(String keyString) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/KW/PKCS5Padding");
        // Cipher cipher = Cipher.getInstance("AESWrap_128");

        // Generate a random iv for the encryption
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()>>1];
        randomSecureRandom.nextBytes(iv);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.WRAP_MODE, secretKeySpec, ivParameterSpec);
        // cipher.init(Cipher.WRAP_MODE, secretKeySpec);
      
        SecretKeySpec key = new SecretKeySpec(keyString.getBytes(), "AES");
      
        byte[] wrapKey = cipher.wrap(key);
   

        // 拼接IV+密文
        /*
         * byte[] message = new byte[iv.length + wrapKey.length]; 
         * System.arraycopy(iv, 0, message, 0, iv.length); 
         * System.arraycopy(wrapKey, 0, message, iv.length, wrapKey.length);
         */
        String ivsString = Base64.getEncoder().encodeToString(iv);
        String wrapKeyString =Base64.getEncoder().encodeToString(wrapKey);

        System.out.printf("IV: %s\n",ivsString);

        return ivsString + ":" + wrapKeyString;
    }

    public String unwrap(String keyString) throws Exception {

        String iVKey[] = keyString.split(":");
        byte[] iv = Base64.getDecoder().decode(iVKey[0]);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        byte[] rawKey = Base64.getDecoder().decode(iVKey[1]);

        Cipher cipher = Cipher.getInstance("AES/KW/PKCS5Padding");
        // Cipher cipher = Cipher.getInstance("AESWrap_128");
        cipher.init(Cipher.UNWRAP_MODE, secretKeySpec, ivParameterSpec);
        SecretKey key = (SecretKey) cipher.unwrap(rawKey, "AES", Cipher.SECRET_KEY);

        return new String(key.getEncoded());
    }

    public static void main(String[] args) throws Exception {
        EncryptUtils.SINGLETON.generateKey();
        String key = "11@中国";

        System.out.println(key);

        String wrapKey = EncryptUtils.SINGLETON.wrap(key);

        System.out.println(wrapKey);
        System.out.println(EncryptUtils.SINGLETON.unwrap(wrapKey));
    }
}