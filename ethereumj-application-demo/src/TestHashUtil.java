import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;

import static org.ethereum.crypto.HashUtil.sha3;
import static org.ethereum.util.ByteUtil.*;

/**
 * Created by prover on 4/26/17.
 */
public class TestHashUtil {
    public static void main(String[] args){

        BigInteger bi = new BigInteger("777777");
        byte[] a = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        byte[] b = bigIntegerToBytes(bi);
        byte[] c = copyToArray(bi);

        a[29] = b[0];
        a[30] = b[1];
        a[31] = b[2];

        b = leftPadZeroTo32Bytes(b);

        String biStr = bi.toString(16);
        System.out.println("0" + biStr);

        byte[] h = sha3(a);
        byte[] h1 = sha3(b);
        byte[] h2 = sha3(c);

        System.out.println(h.length);

        BigInteger hash = bytesToBigInteger(h);
        BigInteger hash1 = new BigInteger(h1);
        BigInteger hash2 = new BigInteger(Arrays.copyOfRange(h2, 0, 32));

        System.out.println(hash.toString(16));
        System.out.println(hash1.toString(16));
        System.out.println(hash2.toString(16));
    }

}

