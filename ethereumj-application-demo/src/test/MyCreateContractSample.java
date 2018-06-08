package test;

import org.ethereum.core.Block;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Transaction;
import org.ethereum.core.TransactionReceipt;
import org.ethereum.crypto.ECKey;
import org.ethereum.db.ByteArrayWrapper;
import org.ethereum.facade.EthereumFactory;
import org.ethereum.listener.EthereumListenerAdapter;
import org.ethereum.solidity.compiler.CompilationResult;
import org.ethereum.solidity.compiler.SolidityCompiler;
import org.ethereum.util.ByteUtil;
import org.ethereum.vm.program.ProgramResult;
import org.spongycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.ethereum.crypto.HashUtil.sha3;
import static org.ethereum.util.ByteUtil.bigIntegerToBytes;
import static org.ethereum.util.ByteUtil.bytesToBigInteger;
import static org.ethereum.util.ByteUtil.copyToArray;


/**
 * Created by Anton Nashatyrev on 03.03.2016.
 */
public class MyCreateContractSample extends MyTestNetSample {

    @Autowired
    SolidityCompiler compiler;

    String contract =
            "pragma solidity ^0.4.0; \n"+
                    "contract Sample { \n" +
                    "  int i;" +
                    "  int public j;" +
                    "  bool flag;" +
                    "  function set_i(int _i) {" +
                    "    i = _i;" +
                    "  } \n" +
                    "  function set_j(int _j) {" +
                    "    j = _j;" +
                    "  } \n" +
                    "  function inc_i(int _i) {" +
                    "    i = i + _i;" +
                    "  } \n" +
                    "  function inc_j(int _j) {" +
                    "    j = j + _j;" +
                    "  } \n" +
                    "  function get_i() constant returns (int) {" +
                    "    return i;" +
                    "  } \n" +
                    "  function get_j() constant returns (int) {" +
                    "    return j;" +
                    "  } \n" +
                    "  function get_sum() returns (int) {" +
                    "    return i + j;" +
                    "  } \n" +
                    "  function get_states() returns (int[3]) {" +
                    "    int[3] memory statesArr;" +
                    "    statesArr[0] = i;" +
                    "    statesArr[1] = j;" +
                    "    statesArr[2] = i + j;" +
                    "    return statesArr;" +
                    "  } \n" +
                    "  function get_sum_hash() constant returns (bytes32) {" +
                    "    return sha3(i + j);" +
                    "  } \n" +
                    "  function get_flag(int num) constant returns (bool) {" +
                    "    bool flag1;" +
                    "    if (i+j+num > 10000) {" +
                    "      flag = true; " +
                    "      flag1 = true;" +
                    "    }" +
                    "    else {" +
                    "      flag = false; " +
                    "      flag1 = false; " +
                    "    }" +
                    "    return flag1;" +
                    "  } \n" +
                    "  function cal_sha3(byte[] a) returns (bytes32) {" +
                    "    return sha3(a);" +
                    "  }\n" +
                    "}";

    private Map<ByteArrayWrapper, TransactionReceipt> txWaiters =
            Collections.synchronizedMap(new HashMap<ByteArrayWrapper, TransactionReceipt>());

    @Override
    public void onSyncDone() throws Exception {

        ethereum.addListener(new EthereumListenerAdapter() {
            // when block arrives look for our included transactions
            @Override
            public void onBlock(Block block, List<TransactionReceipt> receipts) {
                MyCreateContractSample.this.onBlock(block, receipts);
            }
        });

        logger.info("Compiling contract...");
        SolidityCompiler.Result result = compiler.compileSrc(contract.getBytes(), true, true,
                SolidityCompiler.Options.ABI, SolidityCompiler.Options.BIN);
        if (result.isFailed()) {
            throw new RuntimeException("Contract compilation failed:\n" + result.errors);
        }
        CompilationResult res = CompilationResult.parse(result.output);
        if (res.contracts.isEmpty()) {
            throw new RuntimeException("Compilation failed, no contracts returned:\n" + result.errors);
        }
        CompilationResult.ContractMetadata metadata = res.contracts.values().iterator().next();
        if (metadata.bin == null || metadata.bin.isEmpty()) {
            throw new RuntimeException("Compilation failed, no binary returned:\n" + result.errors);
        }

        logger.info("Sending contract to net and waiting for inclusion");
        TransactionReceipt receipt = sendTxAndWait(new byte[0], Hex.decode(metadata.bin));
        logger.info("Contract included!");


        byte[] contractAddress = receipt.getTransaction().getContractAddress();
        logger.info("Contract created: " + Hex.toHexString(contractAddress));
        logger.info("Contract code: " + Hex.toHexString(Hex.decode(metadata.bin)));
        logger.info("Contract ABI: " + metadata.abi.toString());
        logger.info("Verify contract address: " + ethereum.getRepository().isExist(contractAddress));

        logger.info("Calling the contract function 'set'");
        CallTransaction.Contract contract = new CallTransaction.Contract(metadata.abi);
        CallTransaction.Function setI = contract.getByName("set_i");
        CallTransaction.Function setJ = contract.getByName("set_j");
        byte[] functionCallBytes1 = setI.encode(123456);
        byte[] functionCallBytes2 = setJ.encode(654321);
        TransactionReceipt receipt1 = sendTxAndWait(contractAddress, functionCallBytes1);
        TransactionReceipt receipt2 = sendTxAndWait(contractAddress, functionCallBytes2);
        logger.info("Contract modified!");

        logger.info("Calling the contract function 'get'");
        ProgramResult r1 = ethereum.callConstantFunction(Hex.toHexString(contractAddress),
                contract.getByName("get_i"));
        Object[] ret1 = contract.getByName("get_i").decodeResult(r1.getHReturn());
        logger.info("Current contract value i: " + ret1[0]);

        ProgramResult r2 = ethereum.callConstantFunction(Hex.toHexString(contractAddress),
                contract.getByName("get_j"));
        Object[] ret2 = contract.getByName("get_j").decodeResult(r2.getHReturn());
        logger.info("Current contract value j: " + ret2[0]);

        ProgramResult r3 = ethereum.callConstantFunction(Hex.toHexString(contractAddress),
                contract.getByName("get_states"));
        Object[] ret3 = contract.getByName("get_states").decodeResult(r3.getHReturn());
        Object[] rt3 = (Object[]) ret3[0];
        BigInteger rt3_0 = (BigInteger) rt3[0];
        BigInteger rt3_1 = (BigInteger) rt3[1];
        BigInteger rt3_2 = (BigInteger) rt3[2];
        logger.info("Current contract state i: " +(rt3_0));
        logger.info("Current contract state j: " +(rt3_1));
        logger.info("Current contract sum: " +(rt3_2));

        logger.info("Calling the hash of sum");
        logger.info("The hash of sum: " + new BigInteger(sha3(copyToArray(rt3_2))).toString(16));

        ProgramResult r4 = ethereum.callConstantFunction(Hex.toHexString(contractAddress),
                contract.getByName("get_sum_hash"));
        Object[] ret4 = contract.getByName("get_sum_hash").decodeResult(r4.getHReturn());
        byte[] rt4 = (byte[]) ret4[0];
        logger.info("Current contract hash of sum: " + bytesToBigInteger(rt4).toString(16));

        logger.info("Calling the contract function 'get_flag'");
        CallTransaction.Function get_flag = contract.getByName("get_flag");
        byte[] functionCallBytes3 = get_flag.encode(300);
        TransactionReceipt receipt3 = sendTxAndWait(contractAddress, functionCallBytes3);
        byte[] ret5 = receipt3.getExecutionResult();
        System.out.println(new BigInteger(ret5));


        logger.info("Calling the calculate hash 'cal_sha3'");
        CallTransaction.Function cal_sha3 = contract.getByName("cal_sha3");
        byte[] functionCallBytes4 = cal_sha3.encode(777777);
        TransactionReceipt receipt4 = sendTxAndWait(contractAddress, functionCallBytes4);
        byte[] ret6 = receipt4.getExecutionResult();
        System.out.println(new BigInteger(ret6));
        //ProgramResult r5 = ethereum.callConstantFunction(Hex.toHexString(contractAddress),
        //        contract.getByName("get_bool"));
        //Object[] ret5 = contract.getByName("get_bool").decodeResult(r5.getHReturn());
        //Boolean rt5 = (Boolean) ret5[0];
        //logger.info("Current contract sum larger than 1000: " + rt5);

    }

    protected TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data) throws InterruptedException {
        BigInteger nonce = ethereum.getRepository().getNonce(senderAddress);
        logger.info("<=== Sending data: " + Hex.toHexString(data));
        Transaction tx = new Transaction(
                bigIntegerToBytes(nonce),
                ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                ByteUtil.longToBytesNoLeadZeroes(300_000L),
                receiveAddress,
                ByteUtil.longToBytesNoLeadZeroes(0),
                data,
                ethereum.getChainIdForNextBlock());

        tx.sign(ECKey.fromPrivate(senderPrivateKey));
        logger.info("<=== Sending transaction: " + tx);
        ethereum.submitTransaction(tx);
        logger.info("<=== Balance of sender: " + ethereum.getRepository().getBalance(senderAddress));
        logger.info("<=== Hash of transaction: " + Hex.toHexString(tx.getHash()));
        return waitForTx(tx.getHash());
    }

    private void onBlock(Block block, List<TransactionReceipt> receipts) {
        logger.info("Block #" + block.getNumber() + " : " + Hex.toHexString(block.getGasLimit()));
        for (TransactionReceipt receipt : receipts) {
            ByteArrayWrapper txHashW = new ByteArrayWrapper(receipt.getTransaction().getHash());
            if (txWaiters.containsKey(txHashW)) {
                txWaiters.put(txHashW, receipt);
                synchronized (this) {
                    notifyAll();
                }
            }
        }
    }

    private TransactionReceipt waitForTx(byte[] txHash) throws InterruptedException {
        ByteArrayWrapper txHashW = new ByteArrayWrapper(txHash);
        txWaiters.put(txHashW, null);
        long startBlock = ethereum.getBlockchain().getBestBlock().getNumber();

        while(true) {
            TransactionReceipt receipt = txWaiters.get(txHashW);
            if (receipt != null) {
                return receipt;
            } else {
                long curBlock = ethereum.getBlockchain().getBestBlock().getNumber();
                if (curBlock > startBlock + 16) {
                    throw new RuntimeException("The transaction was not included during last 16 blocks: " + txHashW.toString().substring(0,8));
                } else {
                    logger.info("Waiting for block with transaction 0x" + txHashW.toString().substring(0,8) +
                            " included (" + (curBlock - startBlock) + " blocks received so far) ...");
                }
            }
            synchronized (this) {
                wait(20000);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        sLogger.info("Starting EthereumJ!");

        class Config extends MyTestNetConfig{
            @Override
            @Bean
            public MyTestNetSample sampleBean() {
                return new MyCreateContractSample();
            }
        }

        // Based on Config class the BasicSample would be created by Spring
        // and its springInit() method would be called as an entry point
        EthereumFactory.createEthereum(Config.class);
    }
}
