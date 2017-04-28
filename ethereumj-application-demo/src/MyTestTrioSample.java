import com.typesafe.config.ConfigFactory;
import org.ethereum.config.SystemProperties;
import org.ethereum.core.Block;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Transaction;
import org.ethereum.core.TransactionReceipt;
import org.ethereum.crypto.ECKey;
import org.ethereum.db.ByteArrayWrapper;
import org.ethereum.facade.Ethereum;
import org.ethereum.facade.EthereumFactory;
import org.ethereum.listener.EthereumListenerAdapter;
import org.ethereum.mine.Ethash;
import org.ethereum.mine.MinerListener;
import org.ethereum.net.rlpx.Node;
import org.ethereum.net.server.Channel;
import org.ethereum.samples.BasicSample;

import org.ethereum.samples.PrivateMinerSample;
import org.ethereum.solidity.compiler.CompilationResult;
import org.ethereum.solidity.compiler.SolidityCompiler;
import org.ethereum.util.ByteUtil;
import org.ethereum.vm.program.ProgramResult;
import org.spongycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import java.math.BigInteger;
import java.util.*;

import static org.ethereum.crypto.HashUtil.sha3;
import static org.ethereum.util.ByteUtil.bigIntegerToBytes;
import static org.ethereum.util.ByteUtil.bytesToBigInteger;
import static org.ethereum.util.ByteUtil.copyToArray;

/**
 * Created by prover on 4/27/17.
 */
public class MyTestTrioSample  {




    /**********************************************************************/
    /*********************** Dummy Regular Peer ***************************/
    /**********************************************************************/
    /**********************************************************************/
    /**********************************************************************/
    /**
     * Spring configuration class for the regular peer
     */
    private static class RegularPeerConfig {

        private final String peerConfig =
                // no need for discovery in that small network
                "peer.discovery.enabled = false \n" +
                        // set port to 0 to disable accident inbound connections
                        "peer.listen.port = 33333 \n" +
                        "peer.networkId = 31376419 \n" +
                        "peer.privateKey = c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505 \n" +
                        // a number of public peers for this network (not all of then may be functioning)
                        "peer.active = [" +
                        "    { url = 'enode://4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1@128.235.40.193:30001' }," +
                        "    { url = 'enode://466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a@128.235.40.193:30002' }" +
                        "] \n" +
                        "sync.enabled = true \n" +
                        // special genesis for this test network
                        "genesis = genesis.json \n" +
                        "database.dir = peer \n" +
                        "cache.flush.memory = 0";

        @Bean
        public MyTestTrioSample.RegularPeerNode node() {
            return new MyTestTrioSample.RegularPeerNode();
        }
        /**
         * Instead of supplying properties via config file for the peer
         * we are substituting the corresponding bean which returns required
         * config for this instance.
         */
        @Bean
        public SystemProperties systemProperties() {
            SystemProperties props = new SystemProperties();
            props.overrideParams(ConfigFactory.parseString(peerConfig.replaceAll("'", "\"")));
            return props;
        }
    }



    /**
     * Peer bean, which just start a peer upon creation and prints miner events
     */
    static class RegularPeerNode extends BasicSample  {

        public RegularPeerNode() {
            // peers need different loggers
            super("peer" );
        }

        // overriding run() method since we don't need to wait for any discovery,
        // networking or sync events
        @Override
        public void run() {
            super.run();
        }

        @Override
        public void onSyncDone() throws Exception {
            super.onSyncDone();
            byte[] senderPrivateKey = Hex.decode("c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505");
            byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
            logger.info("Peer Balance : " + ethereum.getRepository().getBalance(fromAddress));
        }

    }







    /**********************************************************************/
    /*********************** Dummy Miner One ******************************/
    /**********************************************************************/
    /**********************************************************************/
    /**********************************************************************/
    /**
     * Spring configuration class for the Miner peer
     */
    private static class MinerConfig1 {

        private final String minerConfig1 =
                // no need for discovery in that small network
                "peer.discovery.enabled = true \n" +
                        "peer.listen.port = 30001 \n" +
                        // need to have different nodeId's for the peers
                        "peer.privateKey = 1111111111111111111111111111111111111111111111111111111111111111 \n" +
                        // our private net ID
                        "peer.networkId = 31376419 \n" +
                        // a number of public peers for this network (not all of then may be functioning)
                        "peer.active = [" +
                        "    { url = 'enode://7ee4d7e0a45fcb040b215ed4f842b129e8d7b2e715fafa009a8908044a57b3c1015659b199c3047f47b77c901b35e13b9a42eaa2a5fc6e87ad3764afc2b98682@128.235.40.193:33333' }," +
                        "    { url = 'enode://466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a@128.235.40.193:30002' }" +
                        "] \n" +
                        // we have no peers to sync with
                        "sync.enabled = true \n" +
                        // genesis with a lower initial difficulty and some predefined known funded accounts
                        "genesis = genesis.json \n" +
                        // two peers need to have separate database dirs
                        "database.dir = miner-1 \n" +
                        // when more than 1 miner exist on the network extraData helps to identify the block creator
                        //"mine.extraDataHex = bbbbbbbbbbbbbbbbbbbb \n" +
                        "mine.coinbase = 19e7e376e7c213b7e7e7e46cc70a5dd086daff2a \n" +
                        "mine.cpuMineThreads = 1 \n" +
                        "cache.flush.blocks = 1";

        @Bean
        public MyTestTrioSample.MinerNode1 node() {
            return new MyTestTrioSample.MinerNode1();
        }
        /**
         * Instead of supplying properties via config file for the peer
         * we are substituting the corresponding bean which returns required
         * config for this instance.
         */
        @Bean
        public SystemProperties systemProperties() {
            SystemProperties props = new SystemProperties();
            props.overrideParams(ConfigFactory.parseString(minerConfig1.replaceAll("'", "\"")));
            return props;
        }
    }

    /**
     * Miner 1 bean, which just start a miner upon creation and prints miner events
     */
    static class MinerNode1 extends BasicSample implements MinerListener {

        String number= "1";
        public MinerNode1() {
            // peers need different loggers
            super("miner-1" );
        }

        // overriding run() method since we don't need to wait for any discovery,
        // networking or sync events
        @Override
        public void run() {
            //super.run();
            if (config.isMineFullDataset()) {
                logger.info("Generating Full Dataset (may take up to 10 min if not cached)...");
                // calling this just for indication of the dataset generation
                // basically this is not required
                Ethash ethash = Ethash.getForBlock(config, ethereum.getBlockchain().getBestBlock().getNumber());
                ethash.getFullDataset();
                logger.info("Full dataset generated (loaded).");
            }

            logger.info("Miner " + number + " nodeID: " + bytesToBigInteger(config.nodeId()).toString(16));
            ethereum.getBlockMiner().addListener(this);
            //ethereum.getBlockMiner().setFullMining(true);
            ethereum.getBlockMiner().startMining();
        }

        @Override
        public void miningStarted() {
            logger.info("Miner " + number + " started");
        }

        @Override
        public void miningStopped() {
            logger.info("Miner " + number + " stopped");
        }

        @Override
        public void blockMiningStarted(Block block) {
            //logger.info("Miner " + number + " starts mining block: " + block.getShortDescr());
        }

        @Override
        public void blockMined(Block block) {
            //logger.info("Miner " + number + " mined Block : \n" + block);
            byte[] senderPrivateKey = Hex.decode("1111111111111111111111111111111111111111111111111111111111111111");
            byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
            byte[] toAddress = Hex.decode("2eb9e62aecfe1bf8b5115151903e0daa871e3ce0");
            //logger.info("Miner " + number + " Balance : " + ethereum.getRepository().getBalance(fromAddress));
        }

        @Override
        public void blockMiningCanceled(Block block) {
            //logger.info("Miner " + number + " cancels mining block: " + block.getShortDescr());
        }

    }



    /**********************************************************************/
    /*********************** Dummy Miner Two ******************************/
    /**********************************************************************/
    /**********************************************************************/
    /**********************************************************************/
    /**
     * Spring configuration class for the Miner peer
     */
    private static class MinerConfig2 {

        private final String minerConfig2 =
                // no need for discovery in that small network
                "peer.discovery.enabled = true \n" +
                        "peer.listen.port = 30002 \n" +
                        // need to have different nodeId's for the peers
                        "peer.privateKey = 2222222222222222222222222222222222222222222222222222222222222222 \n" +
                        // our private net ID
                        "peer.networkId = 31376419 \n" +
                        // a number of public peers for this network (not all of then may be functioning)
                        "peer.active = [" +
                        "    { url = 'enode://4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1@128.235.40.193:30001' }," +
                        "    { url = 'enode://7ee4d7e0a45fcb040b215ed4f842b129e8d7b2e715fafa009a8908044a57b3c1015659b199c3047f47b77c901b35e13b9a42eaa2a5fc6e87ad3764afc2b98682@128.235.40.193:33333' }" +
                        "] \n" +
                        // we have no peers to sync with
                        "sync.enabled = true \n" +
                        // genesis with a lower initial difficulty and some predefined known funded accounts
                        "genesis = genesis.json \n" +
                        // two peers need to have separate database dirs
                        "database.dir = miner-2 \n" +
                        // when more than 1 miner exist on the network extraData helps to identify the block creator
                        //"mine.extraDataHex = cccccccccccccccccccc \n" +
                        "mine.cpuMineThreads = 1 \n" +
                        "mine.coinbase = 1563915e194d8cfba1943570603f7606a3115508 \n" +
                        "cache.flush.blocks = 1";

        @Bean
        public MyTestTrioSample.MinerNode2 node() {
            return new MyTestTrioSample.MinerNode2();
        }
        /**
         * Instead of supplying properties via config file for the peer
         * we are substituting the corresponding bean which returns required
         * config for this instance.
         */
        @Bean
        public SystemProperties systemProperties() {
            SystemProperties props = new SystemProperties();
            props.overrideParams(ConfigFactory.parseString(minerConfig2.replaceAll("'", "\"")));
            return props;
        }
    }

    /**
     * Miner 2 bean, which just start a miner upon creation and prints miner events
     */
    static class MinerNode2 extends BasicSample implements MinerListener {

        String number = "2";

        private Map<ByteArrayWrapper, TransactionReceipt> txWaiters =
                Collections.synchronizedMap(new HashMap<ByteArrayWrapper, TransactionReceipt>());

        public MinerNode2() {
            // peers need different loggers
            super("miner-2");
        }

        // overriding run() method since we don't need to wait for any discovery,
        // networking or sync events
        @Override
        public void run() {
            //super.run();
            if (config.isMineFullDataset()) {
                logger.info("Generating Full Dataset (may take up to 10 min if not cached)...");
                // calling this just for indication of the dataset generation
                // basically this is not required
                Ethash ethash = Ethash.getForBlock(config, ethereum.getBlockchain().getBestBlock().getNumber());
                ethash.getFullDataset();
                logger.info("Full dataset generated (loaded).");
            }
            logger.info("Miner " + number + " nodeID: " + bytesToBigInteger(config.nodeId()).toString(16));
            ethereum.addListener(new EthereumListenerAdapter() {
                // when block arrives look for our included transactions
                @Override
                public void onBlock(Block block, List<TransactionReceipt> receipts) {
                    MinerNode2.this.onBlock(block, receipts);
                }
            });
            ethereum.getBlockMiner().addListener(this);
            //ethereum.getBlockMiner().setFullMining(true);
            ethereum.getBlockMiner().startMining();
        }

        @Override
        public void miningStarted() {
            logger.info("Miner " + number + " started");
        }

        @Override
        public void miningStopped() {
            logger.info("Miner " + number + " stopped");
        }

        @Override
        public void blockMiningStarted(Block block) {
            //logger.info("Miner " + number + " starts mining block: " + block.getShortDescr());
        }

        @Override
        public void blockMined(Block block) {
            //logger.info("Miner " + number + " mined Block : \n" + block.getShortDescr());

            byte[] senderPrivateKey = Hex.decode("2222222222222222222222222222222222222222222222222222222222222222");
            byte[] fromAddress = Hex.decode("1563915e194d8cfba1943570603f7606a3115508");
            byte[] toAddress = Hex.decode("2eb9e62aecfe1bf8b5115151903e0daa871e3ce0");
            //logger.info("Miner " + number + " Balance : " + ethereum.getRepository().getBalance(fromAddress));
            BigInteger nonce = ethereum.getRepository().getNonce(fromAddress);
            BigInteger balance = ethereum.getRepository().getBalance(fromAddress);
            byte[] data = new byte[0];
            if (balance.compareTo(new BigInteger("2000000000000")) == 1 && txWaiters.isEmpty()) {
                Transaction tx = new Transaction(
                        ByteUtil.bigIntegerToBytes(nonce),
                        ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                        ByteUtil.longToBytesNoLeadZeroes(1_000_000),
                        toAddress,
                        ByteUtil.bigIntegerToBytes(BigInteger.valueOf(1000000000000L)), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                        data,
                        ethereum.getChainIdForNextBlock());
                tx.sign(ECKey.fromPrivate(senderPrivateKey));
                logger.info("<=== Sending transaction: " + tx);
                ethereum.submitTransaction(tx);
                logger.info("<=== Check transactions: " + ethereum.getWireTransactions().size());
                try {
                    waitForTx(tx.getHash());
                    logger.info("Transaction INCLUDED!");
                } catch (InterruptedException e) {
                    txWaiters.clear();
                    logger.info("Transaction NOT packed.");
                    //e.printStackTrace();
                }
            }
        }

        @Override
        public void blockMiningCanceled(Block block) {
            //logger.info("Miner " + num + " cancels mining block: " + block.getShortDescr());
        }


        private TransactionReceipt waitForTx(byte[] txHash) throws InterruptedException {
            ByteArrayWrapper txHashW = new ByteArrayWrapper(txHash);
            txWaiters.put(txHashW, null);
            long startBlock = ethereum.getBlockchain().getBestBlock().getNumber();

            while(true) {
                TransactionReceipt receipt = txWaiters.get(txHashW);
                if (receipt != null) {
                    txWaiters.remove(txHashW);
                    return receipt;
                } else {
                    long curBlock = ethereum.getBlockchain().getBestBlock().getNumber();
                    if (curBlock > startBlock + 16) {
                        throw new RuntimeException("The transaction was NOT included in last 16 blocks: " + txHashW.toString().substring(0,8));
                    } else {
                        logger.info("Waiting for block with transaction 0x" + txHashW.toString().substring(0,8) +
                                " packed (" + (curBlock - startBlock) + " blocks received so far) ...");
                    }
                }
                synchronized (this) {
                    wait(2000);
                }
            }
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

    }





    /**
     * static main entry
     * @param args
     */

    public static void main(String[] args){

        BasicSample.sLogger.info("Starting EthtereumJ regular peer instance!");
        Ethereum peer = EthereumFactory.createEthereum(MyTestTrioSample.RegularPeerConfig.class);


        BasicSample.sLogger.info("Starting EthtereumJ miner 1 instance!");
        Ethereum miner1 = EthereumFactory.createEthereum(MyTestTrioSample.MinerConfig1.class);

        //miner1.getBlockMiner().startMining();

        BasicSample.sLogger.info("Starting EthtereumJ miner 2 instance!");
        Ethereum miner2 = EthereumFactory.createEthereum(MyTestTrioSample.MinerConfig2.class);
        //miner2.getBlockMiner().startMining();


    }





}
