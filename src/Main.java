 import javax.crypto.Cipher;
 import javax.crypto.SecretKey;
 import javax.crypto.spec.IvParameterSpec;
 import javax.crypto.spec.SecretKeySpec;
 import java.io.InputStream;
 import java.nio.charset.Charset;
 import java.util.Enumeration;
 import java.util.HashMap;
 import java.util.logging.Logger;
 import java.util.zip.ZipEntry;
 import java.util.zip.ZipFile;

 class StringUtil {
     public StringUtil() {
     }

     public String byteArrayToHex(byte[] bytes) {
         if (bytes == null) {
             return null;
         } else {
             StringBuilder sb = new StringBuilder();
             byte[] arr$ = bytes;
             int len$ = bytes.length;

             for (int i$ = 0; i$ < len$; ++i$) {
                 byte b = arr$[i$];
                 sb.append(String.format("%02x ", new Object[]{Integer.valueOf(b & 255)}).toUpperCase());
             }

             return sb.toString().trim();
         }
     }

     public byte[] hexToByteArray(String s) {
         byte[] b = new byte[s.length() / 2];

         for (int i = 0; i < b.length; ++i) {
             int index = i * 2;
             int v = Integer.parseInt(s.substring(index, index + 2), 16) & 255;
             b[i] = (byte) v;
         }

         return b;
     }
 }

public class Main {

    public static void main(String[] args) throws Exception {
        if(args.length == 0){
            System.out.println("command paramter: java Main.class zmkKey inputFileName");
            return;
        }
        String fileName = args[0];
        String zmkKey = args[1];
        // String fileName = "./test.zip";
        // String zmkKey = "00 11 22 33 44 55 66 77";
        byte[] iv = new byte[] { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
        StringUtil ssdStringUtil = new StringUtil();
        Cipher zmkDecryptCipher = Cipher.getInstance("DESede/CBC/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKey keyDecrypt = new SecretKeySpec(ssdStringUtil.hexToByteArray(zmkKey), "DESede");
        zmkDecryptCipher.init(Cipher.DECRYPT_MODE, keyDecrypt, ivParameterSpec);

        //
        HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        ZipFile zipFile = new ZipFile(fileName);
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while(entries.hasMoreElements()){
            ZipEntry entry = entries.nextElement();
            if(entry.getSize() == 0)
                continue;
            InputStream stream = zipFile.getInputStream(entry);
            System.out.println(stream);
            byte[] buffer = new byte[(int)entry.getSize()];
            int len = 0;
            while ((len = stream.read(buffer)) > 0)
            {
                System.out.println(len);
            }
            System.out.println(buffer);
            String v = new String(buffer, Charset.forName("UTF-8"));
            System.out.println(entry.getName());
            System.out.println(entry.getSize());
            System.out.println(v);
            System.out.println(ssdStringUtil.byteArrayToHex(buffer));
            map.put(entry.getName(), buffer);
        }

        System.out.println(map.size());
        //
        byte[] encryptKeyByZmk = map.get("key");
        byte[] randomKey = zmkDecryptCipher.doFinal(encryptKeyByZmk);
        //
        Cipher randDecryptCipher = Cipher.getInstance("DESede/CBC/NoPadding");
        IvParameterSpec randIvParameterSpec = new IvParameterSpec(iv);
        SecretKey randKeyDecrypt = new SecretKeySpec(randomKey, "DESede");
        randDecryptCipher.init(Cipher.DECRYPT_MODE, randKeyDecrypt, randIvParameterSpec);

        for(String key : map.keySet()){
            if(key.equals("key"))
                continue;
            System.out.println(key);
            byte[] buffer = randDecryptCipher.doFinal(map.get(key));
            String v = new String(buffer, Charset.forName("UTF-8"));
            System.out.println("=================================");
            System.out.println(v);
            System.out.println("=================================");
        }
    }
}
