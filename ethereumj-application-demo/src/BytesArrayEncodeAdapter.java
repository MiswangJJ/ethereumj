import java.math.BigInteger;
import org.ethereum.util.ByteUtil;

/**
 * Created by prover on 4/28/17.
 */
public class BytesArrayEncodeAdapter {

    //256 bit is Word length
    //bytes is 8 bit
    //one word needs 32 bytes
    public static byte[] encodeBytesArrayForVerify(byte[] raw){
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

    public static void main (String[] args){
        BigInteger bi = new BigInteger("888888888888888888");
        byte[] biArr = bi.toByteArray();
        byte[] data = encodeBytesArrayForVerify(biArr);
        System.out.println(new BigInteger(data).toString(16));
    }
}
