import com.typesafe.config.ConfigFactory;
import org.ethereum.config.SystemProperties;
import org.ethereum.core.*;
import org.ethereum.crypto.ECKey;
import org.ethereum.db.ByteArrayWrapper;
import org.ethereum.facade.EthereumFactory;
import org.ethereum.listener.EthereumListenerAdapter;
import org.ethereum.samples.BasicSample;
import org.ethereum.util.ByteUtil;
import org.spongycastle.util.encoders.Hex;
import org.springframework.context.annotation.Bean;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * With this simple example you can send transaction from address to address in live public network
 * To make it work you just need to set sender's private key and receiver's address
 *
 * Created by Alexander Samtsov on 12.08.16.
 */
public class MySendTransaction extends BasicSample {


    protected abstract static class TestNetConfig {
        private final String config =
                // network has no discovery, peers are connected directly
                "peer.discovery.enabled = false \n" +
                // set port to 0 to disable accident inbound connections
                "peer.listen.port = 33333 \n" +
                "peer.networkId = 31376419 \n" +
                "peer.privateKey = c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505 \n" +
                // a number of public peers for this network (not all of then may be functioning)
                "peer.active = [" +
                "    { url = 'enode://91d4e09a2fdc40a55ad7839735eb5fd19dbd0621cdc5c5cfb93b45a48a74f90e74279ffcf17e4223e6a88cec240ecdd74cd97bcec9bd58b491933542cd799c3d@100.35.109.150:30379' }," +
                "    { url = 'enode://e58608cc0e8cc8eb636b045949dcbc22489e24df7cc4b7823e5b723f57bd881cebdbb578ec65edd2eff13456dbd7e515321c11c9eb9683e99d83943c3edcbcb0@128.235.40.165:30303' }," +
                "    { url = 'enode://3ee5ea3bdfef825b05bd87d7f0d388e7a42ce234cc56c182040a928d442623574a0f2170a41570cc45c5983bd3596bcd77e90a278f0628d1352be3bef8bdc4e7@128.235.40.185:30303' }" +
                "] \n" +
                "sync.enabled = true \n" +
                // special genesis for this test network
                "genesis = genesis.json \n" +
                "database.dir = testnetExampleDB \n" +
                "cache.flush.memory = 0";

        public abstract MySendTransaction sampleBean();

        @Bean
        public SystemProperties systemProperties() {
            SystemProperties props = new SystemProperties();
            props.overrideParams(ConfigFactory.parseString(config.replaceAll("'", "\"")));
            return props;
        }
    }



    private Map<ByteArrayWrapper, TransactionReceipt> txWaiters =
            Collections.synchronizedMap(new HashMap<ByteArrayWrapper, TransactionReceipt>());


    @Override
    public void onSyncDone() throws Exception {
        ethereum.addListener(new EthereumListenerAdapter() {
            // when block arrives look for our included transactions
            @Override
            public void onBlock(Block block, List<TransactionReceipt> receipts) {
                MySendTransaction.this.onBlock(block, receipts);
            }
        });


        //String toAddress = "e81a50a7a650fea8ce3f61500bb6b68af4d8a26d";
        String toAddress = "f4c6d6c433f60a11ebed2bf81b5073b8d083f1e9";
        logger.info("Sending transaction to net and waiting for inclusion");
        sendTxAndWait(Hex.decode(toAddress), new byte[0]);
        logger.info("Transaction included!");

    }



    private void onBlock(Block block, List<TransactionReceipt> receipts) {
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


    private TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data) throws InterruptedException {

        byte[] senderPrivateKey = Hex.decode("c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505");
        byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
        logger.info("<=== Sender public address: " + Hex.toHexString(fromAddress));
        logger.info("<=== Sender balance: " + ethereum.getRepository().getBalance(fromAddress));
        logger.info("<=== Check receiver's existence: " + ethereum.getRepository().isExist(receiveAddress));
        logger.info("<=== Check random one's existence: " + ethereum.getRepository().isExist(Hex.decode("0000000000000000000000000000000000000000")));
        BigInteger nonce = ethereum.getRepository().getNonce(fromAddress);
        // Amount in ether to send
        BigInteger etherToSend = BigInteger.valueOf(1);
        // Weis in 1 ether
        BigInteger weisInEther = BigInteger.valueOf(1_000_000_000_000_000_000L);
        BigInteger weisToSend = weisInEther.multiply(etherToSend);
        Transaction tx = new Transaction(
                ByteUtil.bigIntegerToBytes(nonce),
                ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                ByteUtil.longToBytesNoLeadZeroes(3_000_000),
                receiveAddress,
                ByteUtil.bigIntegerToBytes(weisToSend), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                data,
                ethereum.getChainIdForNextBlock());

        tx.sign(ECKey.fromPrivate(senderPrivateKey));
        logger.info("<=== Sending transaction: " + tx);
        ethereum.submitTransaction(tx);
        logger.info("<=== Check transactions: " + ethereum.getWireTransactions().size());

        return waitForTx(tx.getHash());

//        return waitForTx(tx.getHash());
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

        class Config extends TestNetConfig {
            @Bean
            public MySendTransaction sampleBean() {
                return new MySendTransaction();
            }
        }

        // Based on Config class the BasicSample would be created by Spring
        // and its springInit() method would be called as an entry point
        EthereumFactory.createEthereum(Config.class);

    }

}