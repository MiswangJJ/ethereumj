package util;

import org.ethereum.core.CallTransaction;
import org.ethereum.util.ByteUtil;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

import static org.ethereum.util.ByteUtil.leftPadZeroTo32Bytes;
import static org.ethereum.util.ByteUtil.merge;

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



    public static byte[] encodeBigIntegerArrayToEtherFormat(BigInteger[] raw){
        int words_num = raw.length;
        int bytes_num = (words_num) * 32;
        byte[] encoded = new byte[bytes_num];

        for (int i = 0; i < raw.length; i++) {
            byte[] tmp = ByteUtil.leftPadZeroTo32Bytes(raw[i].toByteArray());
            for(int j = 0; j < 32; j++) {
                encoded[i*32 + j] = tmp[j];
            }
        }

        byte[] first = ByteUtil.leftPadZeroTo32Bytes(new BigInteger("32").toByteArray());
        byte[] second = ByteUtil.leftPadZeroTo32Bytes(BigInteger.valueOf(words_num).toByteArray());
        return ByteUtil.merge(first, second, encoded);
    }


    public static byte[] encodeMultipleArgs(CallTransaction.Function f, byte[] ... encodedArgs){

        int argsNum = encodedArgs.length;
        byte[][] args = new byte[argsNum][];
        BigInteger[][] inputs = new BigInteger[argsNum][];
        for (int i = 0; i < argsNum; i++){
            args[i] = Arrays.copyOfRange(encodedArgs[i], 32, encodedArgs[i].length);
            inputs[i] = new BigInteger[args[i].length / 32 - 1];
            for (int j = 0; j < inputs[i].length; j++){
                inputs[i][j] = new BigInteger("1");
            }
        }
        byte[] functionCallBytes = merge(f.encodeSignature(), Arrays.copyOfRange(f.encodeArguments(inputs),0,argsNum*32));
        for (int i = 0 ; i < argsNum; i++){
            functionCallBytes = merge(functionCallBytes, args[i]);
        }
        return functionCallBytes;
    }

    public static byte[] encodeMultipleArgs(CallTransaction.Function f, BigInteger arg0, byte[] ... encodedArgs){

        int argsNum = encodedArgs.length;
        byte[][] args = new byte[argsNum][];
        BigInteger[][] inputs = new BigInteger[argsNum][];
        for (int i = 0; i < argsNum; i++){
            args[i] = Arrays.copyOfRange(encodedArgs[i], 32, encodedArgs[i].length);
            inputs[i] = new BigInteger[args[i].length / 32 - 1];
            for (int j = 0; j < inputs[i].length; j++){
                inputs[i][j] = new BigInteger("1");
            }
        }
        Object[] argsObj = new Object[argsNum+1];
        argsObj[0] = arg0;
        for (int i = 0 ; i < argsNum; i++){
            argsObj[i+1] = inputs[i];
        }
        byte[] functionCallBytes = Arrays.copyOfRange(f.encode(argsObj),0,(argsNum+1)*32+4);
        for (int i = 0 ; i < argsNum; i++){
            functionCallBytes = merge(functionCallBytes, args[i]);
        }
        return functionCallBytes;
    }

    public static BigInteger[] hexCipherTextTo32BigIntegers(String cipher){
        BigInteger[] res = new BigInteger[32];
        int zeroPaddingNum = 32 * 16 - cipher.length();
        for (int i = 0; i < zeroPaddingNum; i++){
            cipher = "0" + cipher;
        }
        for(int i = 31; i >= 0; i--){
            res[31-i] = new BigInteger(cipher.substring(i*16, i*16+16), 16);
        }
        return res;
    }

    public static BigInteger[] hexDigestTo8BigIntegers(String digest){
        BigInteger[] res = new BigInteger[8];
        int zeroPaddingNum = 8 * 8 - digest.length();
        for (int i = 0; i < zeroPaddingNum; i++){
            digest = "0" + digest;
        }
        for(int i = 7; i >= 0; i--){
            res[7-i] = new BigInteger(digest.substring(i*8, i*8+8), 16);
        }
        return res;
    }

}
