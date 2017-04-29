package org.ethereum.crypto;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by prover on 4/29/17.
 */
public class Snarks {


    public static int verify (byte[] data){

        final int FALSE = 0xffffffff;
        final int TRUE = 1;

        int verification;

        try {
            parseDataStream(data);
        } catch (IOException | RuntimeException e) {
            //If data is not formatted, then verification fails
            e.printStackTrace();
            return FALSE;
        }

        try {
            verification = run_libsnark_verifier() ?  TRUE : FALSE;
        } catch (Exception e) {
            e.printStackTrace();
            return FALSE;
        }

        return verification;
    }


    /**
     * EVM word stream is received through verify function;
     * EVM has a word length of 256 bits, there is some padding;
     * Parse the EVM word stream to build the serializable for libsnark
     * @param data
     * @throws RuntimeException
     * @throws IOException
     */
    private static void parseDataStream(byte[] data) throws RuntimeException, IOException{

        BigInteger inputLength = null, vkLength, proofLength;

        StringBuffer inputBuffer = new StringBuffer("");

        FileOutputStream primary_input, vk , proof;
        try {
            primary_input = new FileOutputStream("Primary_Input");
            vk = new FileOutputStream("Verification_Key");
            proof = new FileOutputStream("Proof");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            //read public inputs
            int i;
            for (i = 0 ; i < data.length / 32; i++) {
                if (i == 0) {
                    inputLength = new BigInteger(Arrays.copyOfRange(data, 0, 32));
                    inputBuffer.append(inputLength.toString(10)).append(System.getProperty("line.separator"));
                }
                else if (i > 0 && i < inputLength.intValue() + 1) {
                    int ind = i * 32;
                    BigInteger in = new BigInteger(Arrays.copyOfRange(data, ind, ind + 32));
                    inputBuffer.append(in.toString(10)).append(System.getProperty("line.separator"));
                }
                else
                    break;
            }
            inputBuffer.deleteCharAt(inputBuffer.length() - 1);
            primary_input.write(inputBuffer.toString().getBytes());
            primary_input.close();
            //read verification key
            vkLength = new BigInteger(Arrays.copyOfRange(data, i*32, i*32 + 32));
            int i_0 = i + 1;
            i = inputLength.intValue() + vkLength.intValue() + 2;
            vk.write(deleteNulls(Arrays.copyOfRange(data, i_0*32, i*32)));
            vk.close();
            //read proof
            proofLength = new BigInteger(Arrays.copyOfRange(data, i*32, i*32 + 32));
            i_0 = i + 1;
            i = inputLength.intValue() + vkLength.intValue() + proofLength.intValue() + 3;
            proof.write(deleteNulls(Arrays.copyOfRange(data, i_0*32, i*32)));
            proof.close();
        } catch (RuntimeException e){
            System.out.println("Broken snarks or broken EVM data");
            e.printStackTrace();
            throw e;
        } catch (IOException e1){
            e1.printStackTrace();
            throw e1;
        }

    }


    private static byte[] deleteNulls (byte[] raw){
        ArrayList<Byte> tmp = new ArrayList<Byte>();
        for (int i = 0; i < raw.length; i++){
            if(raw[i] != 0){
                tmp.add(raw[i]);
            }
        }
        byte[] res = new byte[tmp.size()];
        for (int i = 0; i < tmp.size(); i++){
            res[i] = tmp.get(i);
        }
        return res;
    }

    private static boolean run_libsnark_verifier() throws Exception {

        Process p;
        p = Runtime.getRuntime()
                .exec(new String[]{"ethereumj-application-demo/res/run_libsnark_verifier"});
        p.waitFor();

        String line;
        BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuffer buf = new StringBuffer();
        while ((line = input.readLine()) != null) {
            buf.append(line + "\n");
        }
        input.close();
        if (buf.toString().contains("* The verification result is: PASS")) {
            return true;
        }
        //System.out.println(buf.toString());
        return false;
    }


}
