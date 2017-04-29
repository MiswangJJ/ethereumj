import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * Created by prover on 4/29/17.
 */
public class TestStringToBigInteger {
    public static void main(String[] args) {
        BigInteger bi =
                new BigInteger("50726976616379203d3d2028457468657265756d202b3d207a6b536e61726b2900000000", 16);
        BigInteger bi1 =
                new BigInteger ("50726976616379203d3d2028457468657265756d202b3d207a6b536e61726b29",16);
        String arg0Str = "Privacy == (Ethereum += zkSnark)";
        final BigInteger bi2 =
                new BigInteger (arg0Str.getBytes());
        System.out.println(bi.equals(bi1));
        System.out.println(bi1.toString(16));
        System.out.println(bi2.toString(16));
    }
}
