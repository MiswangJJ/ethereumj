package util;

import org.ethereum.util.ByteUtil;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

/**
 * Created by prover on 4/28/17.
 */
public class Utils {

    public static byte[] fileToBytes(String path) {

        InputStream in = null;
        try {
            in = new FileInputStream(path);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        // in.available()返回文件的字节长度
        byte[] bytes = null;
        try {
            bytes = new byte[in.available()];
            in.read(bytes);
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bytes;
    }


    //256 bit is Word length
    //bytes is 8 bit
    //one word needs 32 bytes
    public static byte[] encodeBytesArrayToEtherFormat(byte[] raw){
        int words_num = (raw.length / 32) + (raw.length % 32 == 0 ? 0 : 1);
        int bytes_num = (words_num) * 32;
        byte[] encoded = new byte[bytes_num];

        int j = bytes_num - 1;
        for (int i = raw.length - 1 ; i >= 0; i--){
            encoded[j] = raw[i];
            j--;
        }
        byte[] first = ByteUtil.leftPadZeroTo32Bytes(new BigInteger("32").toByteArray());
        byte[] second = ByteUtil.leftPadZeroTo32Bytes(BigInteger.valueOf(words_num).toByteArray());

        return ByteUtil.merge(first, second, encoded);
    }

}
