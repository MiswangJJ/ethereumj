package snarks;

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
import org.ethereum.samples.BasicSample;
import org.ethereum.solidity.compiler.CompilationResult;
import org.ethereum.solidity.compiler.SolidityCompiler;
import org.ethereum.util.ByteUtil;
import org.ethereum.vm.program.ProgramResult;
import org.spongycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import util.Utils;

import java.math.BigInteger;
import java.util.*;

import static org.ethereum.util.ByteUtil.*;
import static util.Utils.encodeBigIntegerArrayToEtherFormat;
import static util.Utils.encodeBytesArrayToEtherFormat;
import static util.Utils.encodeMultipleArgs;

/**
 * Created by prover on 4/28/17.
 */
public class SnarkVerifyBinaryOnesNumber {




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
                        "mine.coinbase = 2eb9e62aecfe1bf8b5115151903e0daa871e3ce0 \n" +
                        "mine.cpuMineThreads = 1 \n" +
                        "cache.flush.memory = 1";

        @Bean
        public SnarkVerifyBinaryOnesNumber.RegularPeerNode node() {
            return new SnarkVerifyBinaryOnesNumber.RegularPeerNode();
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
     * Peer bean, which just start a peer upon creation
     */
    static class RegularPeerNode extends BasicSample {


        protected final static String senderPrivateKeyString = "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505";
        protected final byte[] senderPrivateKey = Hex.decode(senderPrivateKeyString);
        protected final byte[] senderAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();

        @Autowired
        SolidityCompiler compiler;

        String contract =
                "pragma solidity ^0.4.0; \n"+
                        "contract HashSample { \n" +
                        "  address demoAddr = 0x3d7a1426ddbdbf8ddfa23ae5adf5cdc93d801ab1;" +
                        "  bytes32 state;" +
                        "  uint256 inputs_num = 2;" +
                        "  int256[] inputs;" +
                        "  int256[] vk;" +
                        "  int256[] proof;" +
                        "  int256 in1;" +
                        //"  uint256 vk_len;" +

                        "  function get_address() returns (address){" +
                        //"    return address(this);" +
                        "    return demoAddr;" +
                        "  }" +

                        "  function set_vk(int256[] _vk) returns (int256[]){" +
                        "    vk = _vk;" +
                        "    return vk;" +
                        "  }\n" +

                        "  function set_proof(int256[] _proof) returns (int256[]){" +
                        //"    vk = _vk;" +
                        "    proof = _proof;" +
                        "    return proof;" +
                        "  }\n" +

                        "  function set_inputs(int256[] _inputs) returns (int256[]){" +
                        "    inputs = _inputs;" +
                        "    return inputs;" +
                        "  }\n" +

                        "  function set_all(int256[] _vk, int256[] _proof, int256[] _inputs) returns (int256[]){" +
                        "    vk = _vk;" +
                        "    proof = _proof;" +
                        "    inputs = _inputs;" +
                        "    return inputs;" +
                        "  }\n" +

                        "  function set_vk_proof (int _in1, int256[] _vk, int256[] _proof) returns (int256[]){" +
                        "    vk = _vk;" +
                        "    in1 = _in1;" +
                        "    proof = _proof;" +
                        "    return proof;" +
                        "  }\n" +

                        //I did modify the sha3 op code so that 10000 returns no matter what the input is
                        "  function snark_verify() returns (bytes32) {" +
                        "    bytes32 arg0 = \"Privacy == (Ethereum += zkSnark)\";" +
                        "    int256[] memory inputs_mem = new int256[](2);" +
                        "    inputs_mem[0] = 1;" +
                        "    inputs_mem[1] = in1;" +
                        "    state = verify(arg0, inputs_mem.length, inputs_mem, vk.length, vk, proof.length, proof);" +
                        "    return state;" +
                        "  }\n" +

                        "  function get_proof() returns (int256[]) {" +
                        "    return proof;" +
                        "  } \n" +

                        "  function get_vk() returns (int256[]) {" +
                        "    return vk;" +
                        "  } \n" +

                        "  function get_inputs() returns (int256[]) {" +
                        "    return inputs;" +
                        "  } \n" +

                        "}";

        private Map<ByteArrayWrapper, TransactionReceipt> txWaiters =
                Collections.synchronizedMap(new HashMap<ByteArrayWrapper, TransactionReceipt>());

        public RegularPeerNode() {
            // peers need different loggers
            super("peer" );
        }

        @Override
        public void run() {
            //Do NOT override it
            super.run();
        }

        @Override
        public void waitForSyncPeers() throws Exception {
            super.waitForSyncPeers();
            ethereum.addListener(new EthereumListenerAdapter() {
                // when block arrives look for our included transactions
                @Override
                public void onBlock(Block block, List<TransactionReceipt> receipts) {
                    SnarkVerifyBinaryOnesNumber.RegularPeerNode.this.onBlock(block, receipts);
                }
            });
        }

        @Override
        public void onSyncDone() throws Exception {

            super.onSyncDone();


            byte[] senderPrivateKey = Hex.decode("c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505");
            byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
            logger.info("Peer Balance : " + ethereum.getRepository().getBalance(fromAddress));


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
            CallTransaction.Contract contract = new CallTransaction.Contract(metadata.abi);


            TransactionReceipt receipt = null;
            byte[] contractAddress = null;
            int failureCnt = 0;
            while (failureCnt < 10) {
                try {
                    logger.info("The " + (failureCnt + 1) + " trail of sending contract.");
                    receipt = sendTxAndWait(new byte[0], Hex.decode(metadata.bin));
                    contractAddress = receipt.getTransaction().getContractAddress();
                    logger.info("Contract created: " + Hex.toHexString(contractAddress));
                    logger.info("Contract code: " + Hex.toHexString(Hex.decode(metadata.bin)));
                    logger.info("Contract ABI: " + metadata.abi.toString());
                    logger.info("Verify contract address: " + ethereum.getRepository().isExist(contractAddress));
                    logger.info("Contract included!");
                    break;
                } catch (RuntimeException e) {
                    failureCnt++;
                    contractAddress = null;
                    logger.info("Contract NOT packed!");
                    continue;
                }
            } // end of sending contract

//            TransactionReceipt receipt1 = null;
//            if (receipt != null) {
//                failureCnt = 0;
//                while (failureCnt < 10) {
//                    try {
//                        logger.info("The " + (failureCnt + 1) + " trail to set VK by calling 'set_vk'");
//                        CallTransaction.Function set_vk = contract.getByName("set_vk");
//                        byte[] vk = Utils.fileToBytes("ethereumj-application-demo/res/VK_BinaryOnesNumber");
//                        byte[] functionCallBytesPrefix = set_vk.encodeSignature();
//                        byte[] functionCallBytes = merge(functionCallBytesPrefix,
//                                encodeBytesArrayToEtherFormat(vk)
//                        );
//                        logger.info("Set up verification key!");
//                        receipt1 = sendTxAndWait(contractAddress, functionCallBytes);
//                        logger.info("Verification key included!");
//                        //byte[] ret = receipt1.getExecutionResult();
//                        //System.out.println(new BigInteger(ret).toString(16));
//                        break;
//                    } catch (RuntimeException e) {
//                        failureCnt++;
//                        logger.info("VK NOT packed!");
//                        continue;
//                    }
//                }
//            } // end of sending VK
//
//            TransactionReceipt receipt2 = null;
//            if (receipt1 != null) {
//                failureCnt = 0;
//                while (failureCnt < 10) {
//                    try {
//                        logger.info("The " + (failureCnt + 1) + " trail to set VK by calling 'set_proof'");
//                        CallTransaction.Function set_proof = contract.getByName("set_proof");
//                        byte[] proof = Utils.fileToBytes("ethereumj-application-demo/res/Proof_BinaryOnesNumber");
//                        byte[] functionCallBytesPrefix = set_proof.encodeSignature();
//                        byte[] functionCallBytes = merge(functionCallBytesPrefix,
//                                encodeBytesArrayToEtherFormat(proof)
//                        );
//                        logger.info("Set up Proof_Maj_11!");
//                        receipt2 = sendTxAndWait(contractAddress, functionCallBytes);
//                        logger.info("Proof_Maj_11 included!");
//                        //byte[] ret = receipt1.getExecutionResult();
//                        //System.out.println(new BigInteger(ret).toString(16));
//                        break;
//                    } catch (RuntimeException e) {
//                        failureCnt++;
//                        logger.info("Proof_Maj_11 NOT packed!");
//                        continue;
//                    }
//                }
//            } // end of sending Proof_Maj_11
//
//            TransactionReceipt receipt3 = null;
//            if (receipt2 != null) {
//                failureCnt = 0;
//                while (failureCnt < 10) {
//                    try {
//                        logger.info("The " + (failureCnt + 1) + " trail to set VK by calling 'set_inputs'");
//                        CallTransaction.Function set_inputs = contract.getByName("set_inputs");
//                        BigInteger[] inputs = {new BigInteger("1"), new BigInteger("4")};
//                        byte[] functionCallBytesPrefix = set_inputs.encodeSignature();
//                        byte[] functionCallBytes = merge(functionCallBytesPrefix,
//                                encodeBigIntegerArrayToEtherFormat(inputs)
//                        );
//                        logger.info("Set up inputs!");
//                        receipt3 = sendTxAndWait(contractAddress, functionCallBytes);
//                        logger.info("Inputs included!");
//                        //byte[] ret = receipt1.getExecutionResult();
//                        //System.out.println(new BigInteger(ret).toString(16));
//                        break;
//                    } catch (RuntimeException e) {
//                        failureCnt++;
//                        logger.info("Inputs NOT packed!");
//                        continue;
//                    }
//                }
//            } // end of sending Input

//            TransactionReceipt receipt3 = null;
//            if (receipt != null) {
//                failureCnt = 0;
//                while (failureCnt < 10) {
//                    try {
//                        logger.info("The " + (failureCnt + 1) + " trail to set VK Proof_Maj_11 and Inputs by calling 'set_all'");
//                        CallTransaction.Function set_all = contract.getByName("set_all");
//                        byte[] vk = Utils.fileToBytes("ethereumj-application-demo/res/VK_BinaryOnesNumber");
//                        byte[] proof = Utils.fileToBytes("ethereumj-application-demo/res/Proof_BinaryOnesNumber");
//                        BigInteger[] inputs = {new BigInteger("1"), new BigInteger("4")};
//
//                        byte[] encodedVK = encodeBytesArrayToEtherFormat(vk);
//                        byte[] encodedProof = encodeBytesArrayToEtherFormat(proof);
//                        byte[] encodedInputs = encodeBigIntegerArrayToEtherFormat(inputs);
//                        byte[] functionCallBytes = encodeMultipleArgs(set_all,encodedVK, encodedProof, encodedInputs);
//
//                        logger.info("Set up all!");
//                        receipt3 = sendTxAndWait(contractAddress, functionCallBytes);
//                        logger.info("All included!");
//                        //byte[] ret = receipt1.getExecutionResult();
//                        //System.out.println(new BigInteger(ret).toString(16));
//                        break;
//                    } catch (RuntimeException e) {
//                        failureCnt++;
//                        e.printStackTrace();
//                        logger.info("Inputs NOT packed!");
//                        continue;
//                    }
//                }
//            } // end of sending All

            TransactionReceipt receipt3 = null;
            if (receipt != null) {
                failureCnt = 0;
                while (failureCnt < 10) {
                    try {
                        logger.info("The " + (failureCnt + 1) + " trail to set VK Proof_Maj_11 and Inputs by calling 'set_vk_proof'");
                        CallTransaction.Function set_vk_proof = contract.getByName("set_vk_proof");
                        byte[] vk = Utils.fileToBytes("ethereumj-application-demo/res/VK_BinaryOnesNumber");
                        byte[] proof = Utils.fileToBytes("ethereumj-application-demo/res/Proof_BinaryOnesNumber");

                        byte[] encodedVK = encodeBytesArrayToEtherFormat(vk);
                        byte[] encodedProof = encodeBytesArrayToEtherFormat(proof);

                        byte[] functionCallBytes = encodeMultipleArgs(set_vk_proof, new BigInteger("4"), encodedVK, encodedProof);

                        logger.info("Set up VK and Proof_Maj_11!");
                        receipt3 = sendTxAndWait(contractAddress, functionCallBytes);
                        //receipt3 = sendTxAndWait(contractAddress, set_vk_proof.encode(inputs[1], inputs, inputs));
                        logger.info("VK and Proof_Maj_11 included!");
                        //byte[] ret = receipt1.getExecutionResult();
                        //System.out.println(new BigInteger(ret).toString(16));
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        e.printStackTrace();
                        logger.info("VK and Proof_Maj_11 NOT packed!");
                        continue;
                    }
                }
            } // end of sending All


            TransactionReceipt receipt4 = null;
            if (receipt3 != null) {
                failureCnt = 0;
                while (failureCnt < 10) {
                    try {
                        logger.info("The " + (failureCnt + 1) + " trail to verify by calling 'snark_verify'");
                        CallTransaction.Function snark_verify = contract.getByName("snark_verify");
                        //BigInteger[] inputs = {new BigInteger("1"), new BigInteger("9")};
                        //byte[] vk = Utils.fileToBytes("ethereumj-application-demo/res/VK_BinaryOnesNumber");
                        //byte[] proof = Utils.fileToBytes("ethereumj-application-demo/res/Proof_BinaryOnesNumber");
                        byte[] functionCallBytesPrefix = snark_verify.encodeSignature();
                        System.out.println(new BigInteger(functionCallBytesPrefix).toString(16));
                        //System.out.println(new BigInteger(encodeBigIntegerArrayToEtherFormat(inputs)).toString(16));
                        //System.out.println(new BigInteger(encodeBytesArrayToEtherFormat(vk)).toString(16));
                        //System.out.println(new BigInteger(encodeBytesArrayToEtherFormat(proof)).toString(16));
                        byte[] functionCallBytes = merge(functionCallBytesPrefix);
                                //encodeBigIntegerArrayToEtherFormat(inputs),
                                //encodeBytesArrayToEtherFormat(vk),
                                ///encodeBytesArrayToEtherFormat(proof));
                        logger.info("Do verification request!");
                        receipt4 = sendTxAndWait(contractAddress, functionCallBytes);
                        logger.info("Verification result received!");

                        byte[] ret = receipt4.getExecutionResult();

                        System.out.println(bytesToBigInteger(ret).toString());
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        logger.info("Verifying Request NOT packed!");
                        continue;
                    }
                }
            } // end of sending proof and confirm verification

            TransactionReceipt receipt5 = null;
            if (receipt4 != null) {
                failureCnt = 0;
                while (failureCnt < 10) {
                    try {
                        logger.info("The " + (failureCnt + 1) + " trail to get address by calling 'get_address'");
                        CallTransaction.Function get_address = contract.getByName("get_address");
                        byte[] functionCallBytes = get_address.encode();
                        logger.info("Do request address!");
                        receipt5 = sendTxAndWait(contractAddress, functionCallBytes);
                        logger.info("Address result received!");
                        byte[] ret = receipt5.getExecutionResult();
                        System.out.println(bytesToBigInteger(ret).toString(16));
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        logger.info("Verifying Request NOT packed!");
                        continue;
                    }
                }
            } // end of sending proof and confirm verification

//            System.out.println("Proof_Maj_11:");
//            ProgramResult r1 = ethereum.callConstantFunction(Hex.toHexString(contractAddress), contract.getByName("get_proof"));
//            Object[] ret1 = contract.getByName("get_proof").decodeResult(r1.getHReturn());
//            Object[] rt1 = (Object[]) ret1[0];
//            for(int i = 0; i < rt1.length; i++){
//                BigInteger rt1_i = (BigInteger) rt1[i];
//                System.out.println(rt1_i);
//            }
//
//            System.out.println("VK:");
//            ProgramResult r2 = ethereum.callConstantFunction(Hex.toHexString(contractAddress), contract.getByName("get_vk"));
//            Object[] ret2 = contract.getByName("get_vk").decodeResult(r2.getHReturn());
//            Object[] rt2 = (Object[]) ret2[0];
//            for(int i = 0; i < rt1.length; i++){
//                BigInteger rt2_i = (BigInteger) rt2[i];
//                System.out.println(rt2_i);
//            }

//            System.out.println("Inputs:");
//            ProgramResult r3 = ethereum.callConstantFunction(Hex.toHexString(contractAddress), contract.getByName("get_inputs"));
//            Object[] ret3 = contract.getByName("get_inputs").decodeResult(r2.getHReturn());
//            Object[] rt3 = (Object[]) ret3[0];
//            for(int i = 0; i < rt1.length; i++){
//                BigInteger rt3_i = (BigInteger) rt3[i];
//                System.out.println(rt3_i);
//            }

        } // end of onSyncDone method



        protected TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data) throws RuntimeException,InterruptedException {
            BigInteger nonce = ethereum.getRepository().getNonce(senderAddress);
            logger.info("<=== Sending data: " + Hex.toHexString(data));
            Transaction tx = new Transaction(
                    bigIntegerToBytes(nonce),
                    ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                    ByteUtil.longToBytesNoLeadZeroes(50_000_000L),
                    receiveAddress,
                    ByteUtil.longToBytesNoLeadZeroes(0L),
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

        final int BLOCK_NUM_FOR_RESEND = 4;
        private TransactionReceipt waitForTx(byte[] txHash) throws RuntimeException, InterruptedException {
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
                    if (curBlock > startBlock + BLOCK_NUM_FOR_RESEND) {
                        txWaiters.remove(txHashW);
                        throw new RuntimeException("The transaction was NOT included in last " +
                                BLOCK_NUM_FOR_RESEND + " blocks: " + txHashW.toString().substring(0,8));
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

    }






    /*********************************************************************/
    /**************** A semaphore for two dummy miners *******************/
    /**************** otherwise, a danger of dead lock *******************/
    /*********************************************************************/
    private static int flag = 0;


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
                        "mine.extraDataHex = bbbbbbbbbbbbbbbbbbbb \n" +
                        "mine.coinbase = 19e7e376e7c213b7e7e7e46cc70a5dd086daff2a \n" +
                        "mine.cpuMineThreads = 2 \n" +
                        "cache.flush.blocks = 0";

        @Bean
        public SnarkVerifyBinaryOnesNumber.MinerNode1 node() {
            return new SnarkVerifyBinaryOnesNumber.MinerNode1();
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

        private Map<ByteArrayWrapper, TransactionReceipt> txWaiters =
                Collections.synchronizedMap(new HashMap<ByteArrayWrapper, TransactionReceipt>());

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
            ethereum.addListener(new EthereumListenerAdapter() {
                // when block arrives look for our included transactions
                @Override
                public void onBlock(Block block, List<TransactionReceipt> receipts) {
                    SnarkVerifyBinaryOnesNumber.MinerNode1.this.onBlock(block, receipts);
                }
            });
            ethereum.getBlockMiner().setFullMining(true);
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
        public void blockMined(Block block){

            //logger.info("Miner " + number + " mined Block : \n" + block.getShortDescr());

            if( flag == 0 ) {
                flag = 1;
                byte[] senderPrivateKey = Hex.decode("1111111111111111111111111111111111111111111111111111111111111111");
                byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
                byte[] toAddress = Hex.decode("2eb9e62aecfe1bf8b5115151903e0daa871e3ce0");
                //logger.info("Miner " + number + " Balance : " + ethereum.getRepository().getBalance(fromAddress));
                BigInteger nonce = ethereum.getRepository().getNonce(fromAddress);
                BigInteger balance = ethereum.getRepository().getBalance(fromAddress);
                byte[] data = new byte[0];
                if (balance.compareTo(new BigInteger("1000000000000000000")) == 1 && txWaiters.isEmpty()) {
                    Transaction tx = new Transaction(
                            ByteUtil.bigIntegerToBytes(nonce),
                            ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                            ByteUtil.longToBytesNoLeadZeroes(100L),
                            toAddress,
                            ByteUtil.bigIntegerToBytes(BigInteger.valueOf(500_000_000_000_000_000L)), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                            data,
                            ethereum.getChainIdForNextBlock());
                    tx.sign(ECKey.fromPrivate(senderPrivateKey));
                    //logger.info("<=== Sending transaction: " + tx);
                    ethereum.submitTransaction(tx);
                    try {
                        waitForTx(tx.getHash());
                        //logger.info("Transaction INCLUDED!");
                    } catch (Exception e) {
                        //txWaiters.clear();
                        //logger.info("Transaction NOT packed.");
                        //e.printStackTrace();
                    }
                }
            }
            flag = 0;
            synchronized (this) {
                try {
                    wait(777);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void blockMiningCanceled(Block block) {
            //logger.info("Miner " + number + " cancels mining block: " + block.getShortDescr());
        }

        private TransactionReceipt waitForTx(byte[] txHash) throws InterruptedException,RuntimeException {
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
                        txWaiters.remove(txHashW);
                        throw new RuntimeException("Transaction was NOT included last 16 blocks: " + txHashW.toString().substring(0,8));
                    } else {
                        //logger.info("Waiting for block with transaction 0x" + txHashW.toString().substring(0,8) +
                        //        " packed (" + (curBlock - startBlock) + " blocks received so far) ...");
                    }
                }
                synchronized (this) {
                    wait(555);
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
                        "mine.extraDataHex = cccccccccccccccccccc \n" +
                        "mine.cpuMineThreads = 1 \n" +
                        "mine.coinbase = 1563915e194d8cfba1943570603f7606a3115508 \n" +
                        "cache.flush.blocks = 0";

        @Bean
        public SnarkVerifyBinaryOnesNumber.MinerNode2 node() {
            return new SnarkVerifyBinaryOnesNumber.MinerNode2();
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
                    SnarkVerifyBinaryOnesNumber.MinerNode2.this.onBlock(block, receipts);
                }
            });
            ethereum.getBlockMiner().addListener(this);
            ethereum.getBlockMiner().setFullMining(true);
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

            if( flag == 0 ) {
                flag = 2;
                byte[] senderPrivateKey = Hex.decode("2222222222222222222222222222222222222222222222222222222222222222");
                byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
                byte[] toAddress = Hex.decode("2eb9e62aecfe1bf8b5115151903e0daa871e3ce0");
                //logger.info("Miner " + number + " Balance : " + ethereum.getRepository().getBalance(fromAddress));
                BigInteger nonce = ethereum.getRepository().getNonce(fromAddress);
                BigInteger balance = ethereum.getRepository().getBalance(fromAddress);
                byte[] data = new byte[0];
                if (balance.compareTo(new BigInteger("2000000000000000000")) == 1 && txWaiters.isEmpty()) {
                    Transaction tx = new Transaction(
                            ByteUtil.bigIntegerToBytes(nonce),
                            ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice()),
                            ByteUtil.longToBytesNoLeadZeroes(200L),
                            toAddress,
                            ByteUtil.bigIntegerToBytes(BigInteger.valueOf(1_000_000_000_000_000_000L)), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                            data,
                            ethereum.getChainIdForNextBlock());
                    tx.sign(ECKey.fromPrivate(senderPrivateKey));
                    //logger.info("<=== Sending transaction: " + tx);
                    ethereum.submitTransaction(tx);
                    try {
                        waitForTx(tx.getHash());
                        //logger.info("Transaction INCLUDED!");
                    } catch (Exception e) {
                        //txWaiters.clear();
                        //logger.info("Transaction NOT packed.");
                        //e.printStackTrace();
                    }
                }
            }
            //reset semaphore
            flag = 0;
            synchronized (this) {
                try {
                    wait(20000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void blockMiningCanceled(Block block) {
            //logger.info("Miner " + num + " cancels mining block: " + block.getShortDescr());
        }


        private TransactionReceipt waitForTx(byte[] txHash) throws InterruptedException,RuntimeException {
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
                        txWaiters.remove(txHashW);
                        throw new RuntimeException("Transaction NOT included in 16 blocks: " + txHashW.toString().substring(0,8));
                    } else {
                        //logger.info("Waiting for block with transaction 0x" + txHashW.toString().substring(0,8) +
                        //        " packed (" + (curBlock - startBlock) + " blocks received so far) ...");
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
        Ethereum peer = EthereumFactory.createEthereum(SnarkVerifyBinaryOnesNumber.RegularPeerConfig.class);


        BasicSample.sLogger.info("Starting EthtereumJ miner 1 instance!");
        Ethereum miner1 = EthereumFactory.createEthereum(SnarkVerifyBinaryOnesNumber.MinerConfig1.class);

        //miner1.getBlockMiner().startMining();

        BasicSample.sLogger.info("Starting EthtereumJ miner 2 instance!");
        Ethereum miner2 = EthereumFactory.createEthereum(SnarkVerifyBinaryOnesNumber.MinerConfig2.class);
        //miner2.getBlockMiner().startMining();

    }

}
