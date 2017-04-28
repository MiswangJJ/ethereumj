import com.typesafe.config.ConfigFactory;
import org.ethereum.config.SystemProperties;
import org.ethereum.crypto.ECKey;
import org.ethereum.facade.EthereumFactory;
import org.ethereum.samples.BasicSample;
import org.spongycastle.util.encoders.Hex;
import org.springframework.context.annotation.Bean;

/**
 * This class just extends the BasicSample with the config which connect the peer to the test network
 * This class can be used as a base for free transactions testing
 * (everyone may use that 'cow' sender which has pretty enough fake coins)
 *
 * Created by Anton Nashatyrev on 10.02.2016.
 */
public class MyTestNetSample extends BasicSample {
    /**
     * Use that sender key to sign transactions
     */
    //protected final byte[] senderPrivateKey = sha3("cow".getBytes());
    protected final static String senderPrivateKeyString = "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505";
    protected final byte[] senderPrivateKey = Hex.decode(senderPrivateKeyString);
    // sender address is derived from the private key
    protected final byte[] senderAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();

    protected abstract static class MyTestNetConfig {
        private final String config =
                // network has no discovery, peers are connected directly
                "peer.discovery.enabled = true \n" +
                        // set port to 0 to disable accident inbound connections
                        "peer.listen.port = 33333 \n" +
                        "peer.networkId = 31376419 \n" +
                        "peer.privateKey = " + senderPrivateKeyString + " \n" +
                        // a number of public peers for this network (not all of then may be functioning)
                        "peer.active = [" +
                        "    { url = 'enode://5ca673816b405195fc483a161ec7aecd686385693222516944f35f12c8e2c9976a27c61e287d71ac75c8a5deb13e49466e41b3ffc58f7451bf4e371d819fa16c@100.35.109.150:30379' }," +
                        "    { url = 'enode://4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1@128.235.40.193:30001' }," +
                        "    { url = 'enode://466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a@128.235.40.193:30002' }," +
                        "    { url = 'enode://237b183f71309f21f0fdac9c12ddbc265ded3049e1a5482b466219e75deb83ce1b737327a072030a2a28159114f0bc19d3fcc20b6ce8e2e6a9b6ae1d0eb28d1a@128.235.41.160:30000' }," +
                        "    { url = 'enode://08bebe0f3def8ad2316c9f5cb260e92c33677e2e69ceea3c990151c3a0a2b9b32b7c0029bc7c69cb5f02958087a085bfbd4d5bba43df24be7c4af50c4f57996e@128.235.40.193:30000' } " +
                        "] \n" +
                        "sync.enabled = true \n" +
                        // special genesis for this test network
                        "genesis = genesis.json \n" +
                        "database.dir = peer \n" +
                        "cache.flush.memory = 0";


        public abstract MyTestNetSample sampleBean();

        @Bean
        public SystemProperties systemProperties() {
            SystemProperties props = new SystemProperties();
            props.overrideParams(ConfigFactory.parseString(config.replaceAll("'", "\"")));
            return props;
        }
    }

    @Override
    public void onSyncDone() throws Exception {
        super.onSyncDone();
    }

    public static void main(String[] args) throws Exception {
        sLogger.info("Starting EthereumJ!");

        class SampleConfig extends MyTestNetConfig {
            @Bean
            public MyTestNetSample sampleBean() {
                return new MyTestNetSample();
            }
        }

        // Based on Config class the BasicSample would be created by Spring
        // and its springInit() method would be called as an entry point
        EthereumFactory.createEthereum(SampleConfig.class);
    }
}
