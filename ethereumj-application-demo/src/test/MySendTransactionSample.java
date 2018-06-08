package test;

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
public class MySendTransactionSample extends BasicSample {


    protected abstract static class TestNetConfig {
        private final String config =
                // network has no discovery, peers are connected directly
                "peer.discovery.enabled = true \n" +
                        // set port to 0 to disable accident inbound connections
                        "peer.listen.port = 33333 \n" +
                        "peer.networkId = 31376419 \n" +
                        "peer.privateKey = c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505 \n" +
                        // a number of public peers for this network (not all of then may be functioning)
                        "peer.active = [" +
                        "    { url = 'enode://5ca673816b405195fc483a161ec7aecd686385693222516944f35f12c8e2c9976a27c61e287d71ac75c8a5deb13e49466e41b3ffc58f7451bf4e371d819fa16c@100.35.109.150:30379' }," +
                        "    { url = 'enode://6bd37936c78e96ba8228b0236bb44d13ff547a30db1b51b1f3cc117988ac3bd8ecc419b65870492bdfbfab3b469c6fb50c09f0555480580d7cbe26764a4a686e@128.235.40.193:30000' }," +
                        "    { url = 'enode://b723aae027d529c1a91a003f90fb9158cd5f626c31836c1a82d2e72f9264d93111643f153d3b2307d17eb1dbea03b078c99c4ad847431d7a512fbd09f27d2f94@128.235.41.160:30000' } " +
                        "] \n" +
                        "sync.enabled = true \n" +
                        // special genesis for this test network
                        "genesis = genesis.json \n" +
                        "database.dir = testnetExampleDB \n" +
                        "cache.flush.memory = 0";

        public abstract MySendTransactionSample sampleBean();

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
                MySendTransactionSample.this.onBlock(block, receipts);
            }
        });


        String toAddress = "ae4fb9574d06fd89b2a3484d7e258835028fa5b4";
        logger.info("Sending transaction to net and waiting for inclusion");
        sendTxAndWait(Hex.decode(toAddress), new byte[0]);
        logger.info("Transaction included!");

    }


    private TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data) throws InterruptedException {

        byte[] senderPrivateKey = Hex.decode("c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505");
        byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
        logger.info("<=== Sender public address: " + Hex.toHexString(fromAddress));
        logger.info("<=== Sender balance: " + ethereum.getRepository().getBalance(fromAddress));
        logger.info("<=== Check receiver's existence: " + ethereum.getRepository().isExist(receiveAddress));
        logger.info("<=== Check random one's existence: " + ethereum.getRepository().isExist(Hex.decode("0000000000000000000000000000000000000000")));
        BigInteger nonce = ethereum.getRepository().getNonce(fromAddress);
        Transaction tx = new Transaction(
                ByteUtil.bigIntegerToBytes(nonce),
                ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                ByteUtil.longToBytesNoLeadZeroes(3_000_000),
                receiveAddress,
                ByteUtil.bigIntegerToBytes(BigInteger.valueOf(1_000_000_000)), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                data,
                ethereum.getChainIdForNextBlock());

        tx.sign(ECKey.fromPrivate(senderPrivateKey));
        logger.info("<=== Sending transaction: " + tx);
        ethereum.submitTransaction(tx);
        logger.info("<=== Check transactions: " + ethereum.getWireTransactions().size());

        return waitForTx(tx.getHash());

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
            public MySendTransactionSample sampleBean() {
                return new MySendTransactionSample();
            }
        }

        // Based on Config class the BasicSample would be created by Spring
        // and its springInit() method would be called as an entry point
        EthereumFactory.createEthereum(Config.class);

    }

}