package test;

import org.ethereum.crypto.ECKey;
import org.spongycastle.util.encoders.Hex;

/**
 * Created by prover on 4/12/17.
 */
public class TestFromAddress {
    public static void main (String[] args){
        byte[] senderPrivateKey = Hex.decode("1111111111111111111111111111111111111111111111111111111111111111");
        byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
        System.out.println("<=== Sender public address: " + Hex.toHexString(fromAddress));
    }
}
