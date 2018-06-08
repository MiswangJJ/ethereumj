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


/**
 * Created by Anton Nashatyrev on 03.03.2016.
 */
public class MyHashContractSample extends MyTestNetSample {

    @Autowired
    SolidityCompiler compiler;

    String contract =
            "pragma solidity ^0.4.0; \n"+
                    "contract HashSample { \n" +
                    "  function cal_sha3(int256 a) returns (bytes32) {" +
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
                MyHashContractSample.this.onBlock(block, receipts);
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

        CallTransaction.Contract contract = new CallTransaction.Contract(metadata.abi);


        logger.info("Calling the calculate hash 'cal_sha3'");
        CallTransaction.Function cal_sha3 = contract.getByName("cal_sha3");
        byte[] functionCallBytes4 = cal_sha3.encode(new BigInteger("777777"));
        TransactionReceipt receipt4 = sendTxAndWait(contractAddress, functionCallBytes4);
        byte[] ret6 = receipt4.getExecutionResult();
        System.out.println(new BigInteger(ret6).toString(16));

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
                return new MyHashContractSample();
            }
        }

        // Based on Config class the BasicSample would be created by Spring
        // and its springInit() method would be called as an entry point
        EthereumFactory.createEthereum(Config.class);
    }
}
