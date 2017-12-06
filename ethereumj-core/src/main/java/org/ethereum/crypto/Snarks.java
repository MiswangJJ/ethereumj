package org.ethereum.crypto;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.ethereum.crypto.HashUtil.sha3;

/**
 * Created by prover on 4/29/17.
 */
public class Snarks {


    private static int cnt = 0;

    private String path;

    public Snarks(long rnd){
        cnt++;
        path = "snark_verify_dir/" + cnt + "-" + rnd;
    }

    public int verify (byte[] data) throws RuntimeException {


        //String path = "snark_verify_dir/" + cnt;
        new File(path).mkdirs();

        final int FALSE = 0xffffffff;
        final int TRUE = 1;

        int verification;

        try {
            parseDataStream(data, path);
        } catch (IOException | RuntimeException e) {
            //If data is not formatted, then verification fails
            e.printStackTrace();
            return FALSE;
        }

        try {
            verification = run_libsnark_verifier(path) ?  TRUE : FALSE;
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
    private static void parseDataStream(byte[] data, String path) throws RuntimeException, IOException{

        BigInteger inputLength = null, vkLength, proofLength;

        StringBuffer inputBuffer = new StringBuffer("");

        FileOutputStream primary_input, vk , proof;
        try {
            primary_input = new FileOutputStream(path +"/"+ "Primary_Input");
            vk = new FileOutputStream(path +"/"+ "Verification_Key");
            proof = new FileOutputStream(path +"/"+ "Proof");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            //read public inputs (primary inputs)
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

    private static boolean run_libsnark_verifier(String path) throws Exception {

        Process p;
        p = Runtime.getRuntime().exec(
                        new String[]{
                                "ethereumj-application-demo/res/run_libsnark_verifier",
                                path +"/"+ "Verification_Key",
                                path +"/"+ "Primary_Input",
                                path +"/"+ "Proof"
                        });
        p.waitFor();

        String line;
        BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuffer buf = new StringBuffer();
        while ((line = input.readLine()) != null) {
            buf.append(line + "\n");
        }
        input.close();
        p.destroy();
        File file = new File(path + "/log");
        FileOutputStream out = new FileOutputStream(file);
        out.write(buf.toString().getBytes());
        out.flush();
        out.close();
        if (buf.toString().contains("* The verification result is: PASS")) {
            return true;
        }
        //System.out.println(buf.toString());
        return false;
    }



    public static void main(String[] args) throws IOException {

        //String path = "snark_verify_dir/" + 114 + "-" + 4429444200634658255L;
        String path = "snark_verify_dir/7-players";
        //67-2815805291983793877
        File proof = new File(path+"/Proof");
        File input = new File(path+"/Primary_Input");
        File vk = new File(path+"/Verification_Key");

        if(!proof.exists()){
            throw new FileNotFoundException(path+"/Proof");
        }

        if(!input.exists()){
            throw new FileNotFoundException(path+"/Primary_Input");
        }

        if(!vk.exists()){
            throw new FileNotFoundException(path+"/Verification_Key");
        }


        byte[] buf = concat(concat(getBytesFromFile(proof),getBytesFromFile(input)),getBytesFromFile(vk));

        Long start = System.nanoTime();
        sha3(buf);
        Long end = System.nanoTime();
        System.out.println("SHA3 time: " + (end - start));

        start = System.nanoTime();
        sha3(buf);
        end = System.nanoTime();
        System.out.println("SHA3 time: " + (end - start));

        start = System.nanoTime();
        sha3(buf);
        end = System.nanoTime();
        System.out.println("SHA3 time: " + (end - start));

        start = System.nanoTime();
        sha3(buf);
        end = System.nanoTime();
        System.out.println("SHA3 time: " + (end - start));

        start = System.nanoTime();
        sha3(buf);
        end = System.nanoTime();
        System.out.println("SHA3 time: " + (end - start));
    }

    static byte[] concat(byte[] A, byte[] B) {
        byte[] C= new byte[A.length+B.length];
        System.arraycopy(A, 0, C, 0, A.length);
        System.arraycopy(B, 0, C, A.length, B.length);
        return C;
    }

    /**
     * 返回一个byte数组
     * @param file
     * @return
     * @throws IOException
     */
    private  static byte[] getBytesFromFile(File file){

        byte[] bytes = null;
        try {
            InputStream is = new FileInputStream(file);

            // 获取文件大小
            long length = file.length();
            if (length > Integer.MAX_VALUE) {
                // 文件太大，无法读取
                throw new IOException("File is to large " + file.getName());
            }
            // 创建一个数据来保存文件数据
            bytes = new byte[(int) length];
            // 读取数据到byte数组中
            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length
                    && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }
            // 确保所有数据均被读取
            if (offset < bytes.length) {
                throw new IOException("Could not completely read file "
                        + file.getName());
            }
            // Close the input stream and return bytes
            is.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bytes;
    }



}
