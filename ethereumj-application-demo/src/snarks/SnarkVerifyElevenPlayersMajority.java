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
import org.spongycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import util.Utils;

import java.math.BigInteger;
import java.util.*;

import yuan.util.*;

import static org.ethereum.util.ByteUtil.*;
import static util.Utils.encodeBigIntegerArrayToEtherFormat;
import static util.Utils.encodeBytesArrayToEtherFormat;
import static util.Utils.encodeMultipleArgs;

/**
 * Created by prover on 4/28/17.
 */
public class SnarkVerifyElevenPlayersMajority {

    /**
     * Anonymous certificates, there are 11 certificates in total
     */
    static BigInteger[][] tokens = {
            {new BigInteger("3278299071"),
                    new BigInteger("1501744326"),
                    new BigInteger("1960525255"),
                    new BigInteger("536894853"),
                    new BigInteger("270913295"),
                    new BigInteger("644621734"),
                    new BigInteger("3777688356"),
                    new BigInteger("3427313379")},

            {new BigInteger("1369454699"),
                    new BigInteger("1853680140"),
                    new BigInteger("2535405014"),
                    new BigInteger("3002710154"),
                    new BigInteger("3895003205"),
                    new BigInteger("1418033678"),
                    new BigInteger("1418639869"),
                    new BigInteger("3833529393")},

            {new BigInteger("2808647208"),
                    new BigInteger("1401344579"),
                    new BigInteger("1996132067"),
                    new BigInteger("406209377"),
                    new BigInteger("348305636"),
                    new BigInteger("1158341385"),
                    new BigInteger("4009504088"),
                    new BigInteger("3156163986")},

            {new BigInteger("568496348"),
                    new BigInteger("1351437594"),
                    new BigInteger("2106734102"),
                    new BigInteger("1137037511"),
                    new BigInteger("1498939678"),
                    new BigInteger("1401374346"),
                    new BigInteger("3009322840"),
                    new BigInteger("1337198382")},

            {new BigInteger("358077016"),
                    new BigInteger("3610369962"),
                    new BigInteger("2653238332"),
                    new BigInteger("3315691021"),
                    new BigInteger("2992496223"),
                    new BigInteger("2063310751"),
                    new BigInteger("2683724404"),
                    new BigInteger("1489108222")},

            {new BigInteger("2118344153"),
                    new BigInteger("4234996175"),
                    new BigInteger("3541642154"),
                    new BigInteger("2166820308"),
                    new BigInteger("3010729791"),
                    new BigInteger("143585474"),
                    new BigInteger("852674217"),
                    new BigInteger("3617814092")},

            {new BigInteger("4243125847"),
                    new BigInteger("3638030247"),
                    new BigInteger("370654240"),
                    new BigInteger("4001727823"),
                    new BigInteger("251580572"),
                    new BigInteger("1454262996"),
                    new BigInteger("869651122"),
                    new BigInteger("3745860973")},

            {new BigInteger("355389491"),
                    new BigInteger("488505260"),
                    new BigInteger("1527075544"),
                    new BigInteger("713353235"),
                    new BigInteger("851049099"),
                    new BigInteger("1779864952"),
                    new BigInteger("2685072641"),
                    new BigInteger("3089953723")},


            {new BigInteger("2206246298"),
                    new BigInteger("3101758475"),
                    new BigInteger("27026005"),
                    new BigInteger("3914395747"),
                    new BigInteger("19433749"),
                    new BigInteger("2719282328"),
                    new BigInteger("1116527610"),
                    new BigInteger("720230550")},

            {new BigInteger("3864096476"),
                    new BigInteger("2199629292"),
                    new BigInteger("1413038816"),
                    new BigInteger("3633390655"),
                    new BigInteger("92238232"),
                    new BigInteger("1563874032"),
                    new BigInteger("378830065"),
                    new BigInteger("1883243012")},

            {new BigInteger("3281257825"),
                    new BigInteger("2379554042"),
                    new BigInteger("4023027613"),
                    new BigInteger("91855936"),
                    new BigInteger("1598043588"),
                    new BigInteger("4139465758"),
                    new BigInteger("2586596920"),
                    new BigInteger("2548193269")}
    };

    /** p and q are primes of RSA parameters for users' certificates
    static String[] p = {
            "fe27650b5653746c1e3b5baa756511fcf4874c013d6a88f392f658645c2a6acfbc4e3e492e00d47ba1abe9c41730cf49eddfc001a1f3cbbbfb8e21e4c8e253e9f8335a965766004d267e511a490f93b6b0e1611f8862c76aa20e0ce380ada0a60bbc2baf5e1fd07f4eeb4927f77b9da82908187ca69841e30a24ac31ab40b3d1",
            "fbc30ebf1ad5601fe1edfdc24fe2b1963a57baea80e3c22ce09deb9228d421707739c6ac271f94ff3051c93b6e3e7345e71c6117dd0be39815be977641a99d8c70e443438a5b6105336ba48baeb5ab715bb74495dd09a76263cc218eecdbd54b471c5b00270e191ccad86344e34994a0604fd6fb86c76e21286e0727eda5132d",
            "faa045aa56c02a8c6974397288d5b1b71b3be629f8cfb3a8801d9de7d321c07532503d7649ccc363800ebe074125979b64f6bb6b06d3987de448171766f82f41281d4ce1dd5565b9ce316ad6b698d90f3f0793f5553f1f81171f461703f21fafe1ef8c3dee0122f8a721d371437c5bbb384f213087f5bfb107a1ce6a97717c7b",
            "f2f68aa533911ddde9ebb1897c6a7a12b9893d0b83b8c6236c913f1641d2d007eaecbd905f9e6a289a571ab85c3f161292de9d62a1318ef7666afea5748f22db5e5cb2abec545dd514126ca547ae25d8cd2dd38d58a5c6330b9f2220ee764e1e25e6fb3d55873ab9eebe3d4365e527c3aa9126e4c89d53ccec8e2ade4b5cde17",
            "f79752e4361c4313b579e0c3ca24c52e1768fe2f23094fbfb8e0fe6339a9e32a78c9a8628c5215f5a636ca73c1eb58259df4e49d3a44e3424d4b6f8cd76176285b9c83547c246c61b350f1b319762241be18b2303b4fc771a15a1f5d7e6ba0102cdc26484c6ecc5a64d2e3c7cebf16e1cb96bdf005638aefd2e230e455c1f541",
            "facec72eb544048d731185c00fc717321e9dc2b2ac7f8b0c36e8b2b52dc7f99f30d673f3ae8ae8a098c38bcad0c6a5323d020b6b3098b0ab66afdd5a468481116b7ed624fa28754f60dc81427d1eb64ebc4500501bd6a8091cd527b622726a41948a77401c46b2f32b9da424eab39d7778e41bed78c11c6f791ef29f2edc6343",
            "f5d613a94dc4cf8e709e3fc2d362c310966292d0a95836ea8f39f78689943884fd97f9a38a339d9eb9f11eae1179c6786de101cf2df11964eeb4ede7021276f9ce59f2472da59bd3f524fa4a4af0c36844a11043048c684d91c4eb82522b9d547d6f90c8d2d006cbf243f59a602612a04a7739c35d6bc54a6ea042e23dc8a673",
            "fda9d663c23b549397d4da0c505fa9eee111ca094df16a2e3259a20a143dbc194f578f3a9ca05d3ca8da04f0a0c317251c9c602b4dae7852104b89bd20e940f96b89ef3de24bc0da2febf839de97b83ec2e6ea76c7f970a52e3e96aee72945a2da968dc992a577778c04235aee7ae51eb50d602c8ce856e3557256da6fb4caeb",
            "ffd30fb71f5382021b4c5ef0920cbbaf9c8eba1e8b9f466c781ee0f481bb4f7cfce67cd74aa7fc8f825c170a1df95dc01e3ebaf3b124d41f988f537a43fd6f19f32929638532a8fcd31069c5c6fa96c67ca52eabd259b6b146647e5b5e138accb1272994fa28588686843d85df162c32a4c41b7410a8d6cd6ce2cf70ad81532b",
            "fd0ecf31407b852d1f020a962d9bb16f0ae6e1be45779542dd9001b5b9a40c9a11be724144dc3b475def308c7e73d21ae3f6f1fa4f16ae838042e87ae2942cbdf1fae0af8da790a8b22db22e8479a9b1b6964895516c81fb72c7cced6c291bd1d46a6217688cf99a12d29ece848730d77ddc6446b2ad4c5fbb3c41c447d89c53",
            "f4e9f4fd6f95fff60e0024ec93bed0dd9dc62775fb1463b28ddd4b7a8180ad3b1f3f92a711c76113e78acb89eb0ea78a90e41c35f1ac1b95981598ff98f9ed5bdb8d4ebc3bfe88872945de9adfd5385c40f02554a4e749f8d685bca07e7eec019e44058ce70027b37059ded1a9fce791f47c5ce0f8ad4ea88472e3cb666efdbd"
    };

    static String[] q = {
            "f89e579f27d48d7a4bd542a067e8d4d1192bb58873fcd455634dffd220901af04c766ee68f9020f45843d5455f3ec5e3135b2bab13832671530afdb036f522b2e815339001ea198af5cb74699244ef5f4978aae7f5851ffa77d1062c8cc6e6ad775083de9a08274513bb083cfe8c25c4790994a660ce6dd9a249cc6459548745",
            "f4dcd7f3849edda2844f474335c427ed1160266e89aa4d4c6a4167e139f4ae5d9a54ec2a9310d753a977e79aa496c3f2363c76819e7d4bc2f351226649f80423bad8e17ec32fdbf85d277a13e219df055f2fb312e141cb0f31d31c5c561ec4f8b49309a0798dd20203bbb22e3ed99777d6ed259fda4648ea02a2af11a5416d61",
            "f71569d034d69cd24ae072cbaecbe070a35301ccd61206ff921105410c8ae820673221c16a91277b817d2ac93b9b99420099b49665d012f1e9a3e3d94af366bcfdb855ebaff58743c5f5d1a6a3aac8a6b420050d85ab668c46baea37907fa7367a78fc3c9f6755d72bb1caf9016c40d20d5fd315958073905506f14e8c538787",
            "fdf58ea199542e6ee7b670148d2733d06925d53cdfe56c6a939d8f75c868438d749e0f45255c2d950c99905b34e44d1dcc123706bab7927735e2a8f881666ec95f43088d5f4abcfb656bc8681871c48b106d8c3ae4b7751d367e4ddc5de529f5a74c6f8b13dd534e9ce2f3c133a0924308ee1c5acdc07e8039e3a652c4c9d01b",
            "fc9ea6590d11d81d3e1c85a621b4bb62512e793e6bf26c5d622d11256aebaeca88a2af0bc021e9e6649ad8afd6af961ac503e4aa7348fd2f2fd0f4ba7b1d2ec2fdb61604764434a6ec4fee85950fb5c25cc839ba4ee3badd844e4b47bda3aae369806b3c72ba7f3e6248eac45a3cd02267a76206d9b0078f7d8d8b9057b6360b",
            "fdd351883367265437595d259d3fc452109405d4ccd6f0e1248042fe9e251b909c552674f91401af05227d1b57cb7c8101e59621bf13edc1f83a083f22211919345077ef757c29560ba1a6380189daf307803b76bb090cc52689a4bdad43604eada1bb06ab0c45c027f63160ee1a8a437d2423a44e914f5d4e76d2612ddd63f9",
            "fa2f5fd1bd1e6215e191f90f40f3767ba891e13286516892020240fd6c213a3e83fd4216691a241fa45f593c097f2b94b2905de35e15a042f89606c5f8348eaa9e9cbfc65a57eea817b9f49111e607e50d9efbc8d199a006351bb00746b01dfd701118cb7c1a99a217b54d8c089c1d6b78b837545c33a391c272a79be91d30f1",
            "f9a40d42e77aa15fbcdaf96bb46cbce1bfac41bc5a2bdfb152cae8dc8b8330a7abe24527534376819021710c70dadcfa8ae1ff30ae75b733f2d66250faea5831551c806e0a28a1e003508a5dc42b0eb8c62b6fa5d2728ca612fb0cd2083aadfa2ee1895d7b9d5b48255089d98679997e85324b5d0a9b5de62e6d8189aa4e96ab",
            "f530e19fcb71dd41c34298b63b307aa402444be2e377e5295f3565f4c8420c37d4c7a7a131fd1eaa7d401e364d12be706082a469edef099990dd07d92d0786bbca494f99007946eb05c3c113fd8855c288a89bb0da6d97c683d305087bf60b1545a88b96828bb9c9743dd086bea88c3f07e75f40eece0a24c48e6bc1af755949",
            "f5c872c2440bafe967aa41efaa04e9a125dd45c01df08e9b01c0e4957b12a22d5adca38bad06210d7535399e25a6b649184a11fd053d983bcabc71543e8a9e3b69f1be812bf95359f4720d207251b641bbb2faea2e9b1200563aa786b7788bfa08cc44707a8c01ec87b90139c4f88b8e37ffaeda6d70ee0b58020e4ac3fa9b83",
            "fbb6cbfd9a271f01009232ebb784510146703420ef83005477847f5dd3e84bdf906cc7ee2dc524351150e6eeb206c74f6e3d411a3c56897af921957a313f2425268413b3c20c97f9466e2da01f34b7a7394815fcd9cd145aa2c8fd820c5e3ae9a33a33a9024a531e2c236e6c67ab96df6069ca9d5804c4229f97b68bc77c9e45"
    };*/


    /**
     * Some parameter of certificate authority
     */
    static BigInteger[] pCAIn = new BigInteger[16];
    static BigInteger[] qCAIn = new BigInteger[16];
    static BigInteger[] dCAIn = new BigInteger[32];
    static BigInteger[] nCAIn = new BigInteger[32];
    static BigInteger[] nReCAIn = new BigInteger[34];
    static BigInteger[] eCAIn = new BigInteger[1];
    static BigInteger[] tCAIn = new BigInteger[1];
    static BigInteger pCA = new BigInteger("fc904278ac2f9c62c2788f8969437f003f962e8de3c3680bf9174c2e49a7cdf0d5ec5214c179e5733ef0fe55f460ba8695d14bb1c309eaccbb1e98dd7964fc157b54eaa9f6a01ceea57bc44b9e4b7e1608b84e03158d838ac0d6fd0d14b256fc676b6eb1d6157d9c28f8c34feca06dbed102fd3080174bf14d695eaa49bd48db",16);
    static BigInteger qCA = new BigInteger("fd83db33c1cd2c10822719cf233773778923211ea8237a4cadab20197bb1baec72a378947d8e28f5817e6c1ca306814e9ca25ffafd8053794357f202b9234b60a969b8769a0497a6e0ef6517b7da36a3661407288e67ed307a1b729b9f103410e7f53c7e3238713323418e6bf41ae6caf09a939d8f21f3f7e73e6a4e6c003bff",16);



    /**
     * Encryption algorithm parameters
     */
    static BigInteger[] pIn = new BigInteger[16];
    static BigInteger[] qIn = new BigInteger[16];
    static BigInteger[] dIn = new BigInteger[32];
    static BigInteger[] nIn = new BigInteger[32];
    static BigInteger[] nReIn = new BigInteger[34];
    static BigInteger[] eIn = new BigInteger[1];
    static BigInteger[] tIn = new BigInteger[1];

    /**
     *   These are 11 cipher texts of encrypted answers
     */
    static String[] cipherText = {
            "09b107b5213a10baf13d1b3ec92d028dd1e20fee477e4abda8ee7be3b20eca0a7ee9ea256dc6d67eebb556510d3bb021dae01fd461903c49488a87288d130822ab25189ce6f17d77588a94ff478a3ffcbd5a2332ecb875641be58f29f3e99ae9017ad56a442bd99f75c1d4335189b2f5981818b1c8ede0096984b4004eb4555199943647d8a95d48571d00d941e3f56336738db88b895b12917496ed7183fc7186954c0e19434f627bc09234c76e847573fdc19c2d02b583e56bbab370f79400b9e6f2ddac91553d6fd398def57a6638a495334e7e0f43d76d78d31325950429988467262162f2f37082822b0640eeda252ccf42f510482c9cadd0719a67fffc",
            "97c9f4b94b9074185865d73417553d8026470f7f1e6ce82e47b14c9dda5723dc8499cd757948b9d9945cf8634d217ed65e98f583053593bd5a52682285724d84f07d340b59a64ab7f3b879fbf061c27a73032bb3ab962ce8b4f9379d1d4a76999214bc8bf5801427d9a2f33d1660fdfa829fa832b58709616546bc0cafc6a44b2d118362b8b9af398095e83a006e39b1e513ad2f7c647d468717de59af684afa65d597e4757701d73c18a8acf8ff391e72cb8d4dfc662f2dc6b6cb9bcb7f4a42e070fd1238bf9d5b7da0c01251c738d01b8716a99393f2a939f43e315e354109d30c4d610662d61c94bc49bc1c550cda59d9d9ab9a40751c36481c17bc96d0a0",
            "dfe6189f8886c7e2220abdd803407c8f99fbf47119a7b5d9d3ca831d5b822f9c159bca040611ece490243f2a13307429e51b942c72d6fd4b6015f1d3bd440e7680f29e873ec1a157862cfd83a4531046687d65dc5f61435bbd2751c797944fa8d358a9d499ff51ade8e8ce6e73faa67ce72b1f923dda2955b78f47a10f073dd5e09af31f55fe1d06b9ed64f8d28f1e8eb06b2cc15f2cd8d95e75ad28de8156925825459fd5c9659f947b0e87fbdb0dd5e42a283a35d9f601a356d3ca57a88479e911cbe20f8bec04aa49cccd44ce157c746f6a543d3a3641897e228423c7954fc7c0d9b06f7ab7a4f882af6095f6f0dff7d582925b065096f1c37e264b82ac1b",
            "05fdba23dbb0c79a12e37ce217d114c73fb0df8d404e67e4691ecb193f1c365a4076c0c3dc35df0895b38618f0ad7c346c3d3a3e0229663dbece43d61db9cb1a37b1e672c3d7132fe75fc3a6bd1e014ddbdd421b1a86aeabaaa32a3bf19c7026a1d2d7b5a11b3ed0995d6d5602c22dd5ce1516a32e2c5ab06cf102b277559e1e2f1d9f9a33cdda4964ee11ae89e860b939c02d87c4a6dc34584e5a042ed3d37adca45eea248d3df41cb7f865a883a15d1ffa2bbe91c1c71b5efd97d99245d72c82995be1614ad9def698532097f328d2f50ad309afbc9c3c5cc0f53ea4deb0b5ebc7c9227b541db6196ad1d89c1c434710e891ff3c8bc8e241e7e38d744b90cf",
            "e8c089f45e94060abc91716d7438f6eaba4f4ba8a247d1d9955660ae5ba0cafa80256387585c49a759b61136d8f2f01bd4e314636f3e7e88af20fdc4a5eab5903ca7af4dbf7269fdc0055f8c37f0497eb3de2bf4d07770fc10c57a7026bd7b9b046d99e810e26219d44e9eb499a03e5bbd0d04b6f4b9799d9a676bcd45bf968c8d584bc7bffb52cfd41168d094e832327db4d50ace1b73088ad18bc76511d9de8c8a1f80077209bbde1ed1f0c0bfc417ebe8de8d5446eead01008dd934deb63f927630751a7c0112e6b74c9e34abc6f07cead7986f5adeda98171ff91c295cba67f3769425fb236f3b333be8fe4f12d8b449f4b9351a4f9394e0bca63e5194a4",
            "898213873eedc4c1754ab0eeb356173f08d4cf63ed845812e82bb76148a77a6769b1521010cb2d1751d317b068cd9250af531f6a177f1c75898eaaa84466c2cca571efdc04b03ef96a2dd32cd3476862062722aba3223f6bd9f10a25403e67b9ed3e17fb2d0371c5893fb0d21b91681d4a6ca508fd285e7cac46c52c299d6e08b999594ccb1d6ae64699aa09f77c698339e17bdbcc47a0976ab8b708e7b11f16adba530a86d935be10c25fb937c0ab631c5880623210e7c1feeb05537ffed1d20a9f870423054099140419b69f39fb454627a822fdf08f59140141746f2359d4d121a3868b786bc88216f4a62a29c2836d9218df9d1983129cc99af1c804a3cb",
            "2d7e7a6fd7465a3fdfae493e4bcf3a2119de52f2b9166fb82471cc29b19edd22740fcdd667ac39372661d519fc28bb3901e0de1372332dee11bfb118db9414f7e0c808425c7c003cc017126ef7a5f709aff91b14a612c8d179e5bef512003938aa0eb456db47a1da03583a5c6872dd4f498ef5e67209ba35368f239dc1cb7104ba1a5173223f1db567c911f08111cdaed27fab42b78312bb87e41ee0efb671380ed723b16b317847000179d0aa46389534cffb09dff0260eb0cd0a1f3a790d8e65fe264871fad616831b7141a6fc33b8dcb2ebd02a5eb398b109e8f57feab0bc11023994149b8bf03af62179638a639486b7e2e5c704e28139798eb8d55a5d39",
            "8455da51d5b9d0216d4a4a9913c93189a67c5200be1893587bbb6c9b0f54f2d7640b195a7fa3066a2e4bb08caccbc674de5b6be0e69632214c8e41855fb312c55164b81a16719e36732175037cd0eefb3264fa67ba9c0dbb0ffdda85369567887ea246c1fe57d820372282ac5152e2ea02c804d0b170073498fe77a7094a5f223a3d6642b30e40612fbd6d7f5a02deb8c58ba392c1b8d6eafe48da2c0b85cd35e9c7d32e6734a60d8315aed6f9aec45245c76949fa23fc36f8b8c889f7dce07a0ffc4fad551f26e8439da626d8651aa3a8eae34b42f0bbce5f9077213f819b09769204d752fd619f395deee4e358c1e8892c04557a5c8bf78cc5ff70a97c8bc5",
            "40c2038899f1c2fabd5713fe7728596014f76f855d68838e94b109fba955e46f4dc9ade9a286e1158931f6a8fc4f1b3ca285aa59c23780e7096d9018b264afffe63a458642315c7a04437a929d87da6514901115670ee12d5476951e9543f359ae5b8a2ed09618ced12575ebe9caa348f43818af5cc0b54cb1ed40fa98a73121fc6396f19a666d1e3ee1e9a4d2af421e2b977392b6e1f8a5fd49eaf67ee6fa993ed927c5ec4cfc9017360c0ae54e786d9b95fe7e2f6501fb7760ff832ab2d326f31fedefcc2dc12c66f8c54640054e15018de546a723efa5b4eaa2e6e44507efcf377a4654515598552d0b168c274835301644dc419ea9323c5d064506fd1383",
            "c9032a328db0e4933c0e4d71f6e9ee3be863827079380a9c50022ea03efdd44ee5c37f5f57362d3d8611b579ad355a72e99535df9cae5341fc0dc2b8202da68b70b9cd1246ac6b6ee7c7fb658994634268b989134236dc1830236faccce9dd37ac7ecbd2094b71e783e062ec12f1ecde62d822ea4d8e321131b5849329f15e43677c1c12eec9335bb399b0201287d21b2d8ae1a67ade426e0f3deeae72cf3cc62be1cdf7608ca4c530ef84acd8ff0c453bdc3d886ca724f3d737a3c0fd5948c5844e498d4abd8fad3275ccfdb231dca821ac7b1855e7e61d21cdc6b881422dacc26c41cae78891419678ca7b7e6846ecbf5c232d24468ba106380094f93c1d3a",
            "8ecfbd360bf174469acdcb76afdca1fdd509099ca02b84ea4001ff109de1614cdd5521acd34410cda7588482e3968ee657a0b24763fece76753e0724ec1d1ac3bf2514f670573a755f6f6cdd2c2226ddacee74e2a0ce3bfe4eb574a3c23e49e6b20fd15dd9258fe778ab631afd7a0b2ed1bf05168bff80bb29b7c5570c73f23394012373136e15f028e53077bce663d93d629f39c3a43b569b7bdd73ada40260ea11d9b1a6197286b9e7562aab737d2106a8c5f3536a1961620ee905273328b4e4dc5c5c8d08249e43c81cb09c0c862d5e35be56904d68de418b653bb8448b06e236f74b4fa89674bbb16d922d26302f3440085658da768bbc8691eba1295f37"
    };

    /**
     * These are plaintext of 11 answers
     */
    static BigInteger[] isMaj = {
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.ONE
    };
    static BigInteger majCount = new BigInteger("6");
    static String majDigest = "c1c78a847134593d9de066cc9bf65009d94f1219904660d67440acfb5a3a5b05";

    /**********************************************************************/
    /********************** Dummy Requester Peer **************************/
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
                        "    { url = 'enode://4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1@127.0.0.1:30001' }," +
                        "    { url = 'enode://466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a@127.0.0.1:30002' }" +
                        "] \n" +
                        "sync.enabled = true \n" +
                        // special genesis for this test network
                        "genesis = genesis.json \n" +
                        "database.dir = peer \n" +
                        //"mine.coinbase = 2eb9e62aecfe1bf8b5115151903e0daa871e3ce0 \n" +
                        //"mine.cpuMineThreads = 1 \n" +
                        "cache.flush.memory = 0";

        @Bean
        public SnarkVerifyElevenPlayersMajority.RegularPeerNode node() {
            return new SnarkVerifyElevenPlayersMajority.RegularPeerNode();
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

        protected  final static String[] participantsPrivateKeyStrings = {
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a111111111",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a222222222",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a333333333",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a444444444",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a555555555",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a666666666",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a777777777",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a888888888",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a999999999",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7aaaaaaaaaa",
                "c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a000000000" };

        @Autowired
        SolidityCompiler compiler;

        String contract =
                "pragma solidity ^0.4.0; \n"+
                        "contract Task { \n" +

                        "  uint public deposit;" +
                        "  bool public initialized;"+
                        "  bool public ended;" +
                        "  bool public deposit_refunded;" +
                        "  bool public bonus_funded;" +
                        "  uint public token_deposit;" +
                        "  uint public bonus;" +
                        "  uint public first_data_bonus;" +
                        "  bytes32 public state;" +
                        "  address buyer;" +

                        "  address demoAddr = 0x3d7a1426ddbdbf8ddfa23ae5adf5cdc93d801ab1;" +
                        "  int256[] ca_mod_base;" +
                        "  int256[] ca_mod_base_re;" +
                        "  int256[] ca_vk;" +

                        "  struct Participant {" +
                        "    int256[] enc_data;" +
                        "    int256[] anonymous_token;" +
                        "    address one_time_address;" +
                        "    int256 is_maj;" +
                        "    bool is_paid;" +
                        "  }\n" +

                        "  Participant[] participants;" +

                        "  uint256 participants_limit;" +
                        "  uint256 participants_num;" +
                        "  int256[] vk;" +
                        "  int256[] mod_base;" +//32
                        "  int256[] mod_base_re;" +//34
                        "  int256 public_exp;" +

                        "  int256[] proof;" +
                        //"  int256[] isMaj;" +
                        "  int256[] majDigest;" +
                        "  uint256 majCount;" +

                        "  function Task() payable {" +
                        "    buyer = msg.sender;" +
                        "    bonus = 1000000000000000;" +
                        "    token_deposit = 0;" +
                        "    first_data_bonus = 600000000000000;" +
                        "    state = 0;" + //state=0 represents waiting for initialization
                        "    initialized = false;" +
                        "    ended = false;" +
                        "    deposit_refunded = false;" +
                        "    bonus_funded = false;" +
                        "    deposit = msg.value;" +
                        "  }\n" +


                        "  function init (uint256 _participants_limit, " +
                        "                 int256[] _mod_base, int256[] _mod_base_re, int256[] _vk, " +
                        "                 int256[] _ca_mod_base, int256[] _ca_mod_base_re, int256[] _ca_vk) " +
                        "                 payable returns (uint) {" +
                        "    require(!initialized);" +
                        "    if(state != 0 || buyer != msg.sender){" +
                        "      throw;" +
                        "    }" +
                        "    deposit = deposit + msg.value;" +
                        "    participants_limit = _participants_limit;" +
                        "    if (deposit <= 2 * participants_limit * bonus + first_data_bonus){" +
                        "      throw;" +
                        "    }" +
                        "    public_exp = 3;" +
                        "    mod_base = _mod_base;" +
                        "    mod_base_re = _mod_base_re;" +
                        "    vk = _vk;" +
                        "    ca_mod_base = _ca_mod_base;" +
                        "    ca_mod_base_re = _ca_mod_base_re;" +
                        "    ca_vk = _ca_vk;" +
                        "    participants_num = 0;" +
                        "    state = 1;" + //state=1 represents being collecting data
                        "    initialized = true;" +
                        "    return this.balance;" +
                        "  }\n" +


                        "  function submit_data (int256[] _token, int256[] _proof, int256[] _enc_data) payable returns (bool) {" +
                        "    if (state != 1 || _enc_data.length != 32 || _token.length != 8 ) {" +
                        "      throw;" +
                        "    }" +
                        "    if (msg.value < token_deposit) {" +
                        "      throw;" +
                        "    }" +
                        "    uint inputs_num = 1 + 1 + 1 + 32 + 34 +8;" +
                        "    int256[] memory inputs = new int256[](inputs_num);" +
                        "    inputs[0] = 1;" +
                        "    inputs[1] = int256(demoAddr);" +
                        "    inputs[2] = public_exp;" +
                        "    uint i;" +
                        "    for (i = 0; i < 32; i++) {" +
                        "      inputs[i+3] = ca_mod_base[i];" +
                        "    }" +
                        "    for (i = 0; i < 34; i++) {" +
                        "      inputs[i+35] = ca_mod_base_re[i];" +
                        "    }" +
                        "    for (i = 0; i < 8; i++) {" +
                        "      inputs[i+69] = _token[i];" +
                        "    }" +
                        "    bytes32 certified = snark_verify(inputs, ca_vk, _proof);" +
                        "    bool valid = (certified == 200 && is_duplicated_token(_token) != 1);" +
                        "    if (valid) {" +
                        "       participants.push(Participant({" +
                        "                     enc_data: _enc_data, " +
                        "                     anonymous_token: _token, " +
                        "                     one_time_address: msg.sender," +
                        "                     is_maj: 1," +
                        "                     is_paid: false}));" +
                        "       participants_num = participants.length;" +
                        "       if (participants_num == participants_limit) {" +
                        "           state = 2;" + //state=2 represents waiting for proof of incentive allocation
                        "       }" +
                        "       msg.sender.transfer(msg.value);" +
                        "    }" +
                        "    return valid;" +
                        "  }\n" +


                        "  function is_duplicated_token (int256[] _token) internal returns (bytes32) {" +
                        "    uint i;" +
                        "    for (i = 0; i < participants.length; i++) {" +
                        "      int flag = 1;" +
                        //"      int256[] memory token = participants[i].anonymous_token;" +
                        "      for (uint j = 0; j < 8; j++) {" +
                        "        if (participants[i].anonymous_token[j]  != _token[j]) {" +
                        "          flag = 0;" +
                        "        }" +
                        "      }" +
                        "      if (flag == 1) {" +
                        "        return 1;" +
                        "      }" +
                        "    }" +
                        "    return 0;" +
                        "  }\n" +


                        "  function end (uint256 _majCount, int256[] _majDigest, int256[] _isMaj, int256[] _proof) returns (bytes32) {" +
                        "    require(!ended);" +
                        "    if(state != 2 || buyer != msg.sender){" +
                        "      throw;" +
                        "    }" +
                        "    majCount = _majCount;" +
                        "    majDigest = _majDigest;" +
                        //"    isMaj = _isMaj;" +
                        "    proof = _proof;" +
                        "    uint inputs_num = 1 + 1 + 32 + 34 + 1 + participants_limit + 8 + 32 * participants_limit;" +
                        "    int256[] memory inputs = new int256[](inputs_num);" +
                        "    inputs[0] = 1;" +
                        "    inputs[1] = public_exp;" +
                        "    uint i;" +
                        "    for (i = 0; i < 32; i++) {" +
                        "      inputs[i+2] = mod_base[i];" +
                        "    }" +
                        "    for (i = 0; i < 34; i++) {" +
                        "      inputs[i+34] = mod_base_re[i];" +
                        "    }" +
                        "    inputs[68] = int256(majCount);" +
                        "    for (i = 0; i < 8; i++) {" +
                        "      inputs[i+69] = majDigest[i];" +
                        "    }" +
                        "    for (i = 0; i < _isMaj.length; i++) {" +
                        "      inputs[i+77] = _isMaj[i];" +
                        "    }" +
                        "    for (i = 0; i < participants_limit; i++) {" +
                        "      for (uint j = 0; j < 32; j++) {" +
                        "        inputs[i*32 + j + 77 + _isMaj.length] = participants[i].enc_data[j];" +
                        "      }" +
                        "    }" +
                        "    state = snark_verify(inputs, vk, proof);" +
                        "    if (state==200){" +
                        "      for (i = 0; i < participants.length; i++) {" +
                        "        participants[i].is_maj = _isMaj[i];" +
                        "      }" +
                        "    } " +
                        "    ended = true;" +
                        "    return state;" +
                        "  }\n" +

                        "  function fund_bonus() returns (uint) {" +
                        "    require(ended);" +
                        "    require(!bonus_funded);" +
                        "    uint amount;" +
                        "    participants[0].one_time_address.transfer(first_data_bonus);" +
                        "    if(state==200) {" +
                        "       if (this.balance >= majCount * bonus) {" +
                        "           amount = bonus;" +
                        "       } else {" +
                        "           amount = this.balance / majCount;" +
                        "       }" +
                        "       uint i;" +
                        "       for (i = 0; i < participants.length; i++) {" +
                        "          if(participants[participants.length - i - 1].is_maj == 1){" +
                        "             if (this.balance >= amount) {" +
                        "                participants[participants.length - i - 1].one_time_address.transfer(amount);" +
                        "             } else {" +
                        "                participants[participants.length - i - 1].one_time_address.transfer(this.balance);" +
                        "             }" +
                        "          }" +
                        "       }" +
                        "    }" +
                        "    else {" +
                        "       amount = this.balance / participants.length;" +
                        "       for (i = 0; i < participants.length; i++) {" +
                        "          if (this.balance >= amount) {" +
                        "             participants[participants.length - i - 1].one_time_address.transfer(amount);" +
                        "          } else {" +
                        "             participants[participants.length - i - 1].one_time_address.transfer(this.balance);" +
                        "          }" +
                        "       }" +
                        "    }" +
                        "    bonus_funded = true;" +
                        "    return this.balance;"+
                        "  }"+

                        "  function refund_deposit() {" +
                        "    require(ended);" +
                        "    require(bonus_funded);" +
                        "    require(!deposit_refunded);" +
                        "    if(msg.sender != buyer) {" +
                        "      throw;" +
                        "    }" +
                        "    msg.sender.transfer(this.balance);" +
                        "    deposit_refunded = true;" +
                        "  }"+

                        "  function snark_verify(int256[] _inputs, int256[] _vk, int256[] _proof) internal returns (bytes32) {" +
                        "    bytes32 _state;" +
                        "    bytes32 arg0 = \"Privacy == (Ethereum += zkSnark)\";" +
                        "    if (verify(arg0, _inputs.length, _inputs, _vk.length, _vk, _proof.length, _proof) == 1) {" +
                        "        _state = 200;" + // state=200 represents proof is passed
                        "    } else {" +
                        "        _state = 500;" + //state=404 represents proof is failed
                        "    }" +
                        "    return _state;" +
                        "  }\n" +

                        "  function kill() {" +
                        "    require(ended);" +
                        "    require(bonus_funded);" +
                        "    require(deposit_refunded);" +
                        "    if (msg.sender == buyer) suicide(buyer); " +
                        "  }"+

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
                    SnarkVerifyElevenPlayersMajority.RegularPeerNode.this.onBlock(block, receipts);
                }
            });
        }

        @Override
        public void onSyncDone() throws Exception {

            super.onSyncDone();


            byte[] senderPrivateKey = Hex.decode("c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505");
            byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();

            //logger.info("Peer Balance : " + ethereum.getRepository().getBalance(fromAddress));

            int failureCnt;




            /**
             * 0. Fund participants account
             */
            boolean initial_fund_switch = false;
            if (initial_fund_switch) {
                for (int i = 0; i < 11; i++) {
                    failureCnt = 0;
                    while (failureCnt < 10) {
                        String participant = participantsPrivateKeyStrings[i];
                        byte[] participantPrivateKey = Hex.decode(participant);
                        byte[] participantAddress = ECKey.fromPrivate(participantPrivateKey).getAddress();
                        try {
                            logger.info("The " + (failureCnt + 1) + " trail of funding participant " + i);
                            long fund = 1_000_000_000_000_000_000L;
                            sendTxAndWait(participantAddress, new byte[0], fund, 40000000);
                            logger.info("Participant " + i + " funded!");
                            break;
                        } catch (RuntimeException e) {
                            failureCnt++;
                            logger.info("Transaction NOT packed!");
                            continue;
                        }
                    }
                    Thread.sleep(5000);
                }
            }


            BigInteger[] initialBalances = new BigInteger[12];
            //System.out.println("Initial balances:");
            initialBalances[0] = ethereum.getRepository().getBalance(fromAddress);
            System.out.println(initialBalances[0]);
            for (int i = 0; i < 11; i++) {
                String participant = participantsPrivateKeyStrings[i];
                byte[] participantPrivateKey = Hex.decode(participant);
                byte[] participantAddress = ECKey.fromPrivate(participantPrivateKey).getAddress();
                initialBalances[i + 1] = ethereum.getRepository().getBalance(participantAddress);
                //System.out.println(initialBalances[i + 1]);
            }


            /**
             * 1. Send out the Contract of crowdsourcing task
             */
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
            failureCnt = 0;
            while (failureCnt < 10) {
                try {
                    logger.info("The " + (failureCnt + 1) + " trail of sending contract.");
                    receipt = sendTxAndWait(new byte[0], Hex.decode(metadata.bin), 1_000L,3000000);
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

            Thread.sleep(500);



            /**
             * 2. The owner initialized the task with task parameters and encryption parameters
             */

            TransactionReceipt receipt1 = null;
            if (receipt != null) {
                //"  function init(uint256 _participants_limit, int256[] _mod_base, int256[] _mod_base_re, int256[] _vk) {"
                RSAKeyComponents rsaKeyComponents = RSAOAEPAlgorithms.generateRSAKeyComponents(pIn, qIn, dIn, nIn, nReIn, eIn, tIn);
                RSAOAEPAlgorithms.generateRSAKeyComponents(pCA, qCA, pCAIn, qCAIn, dCAIn, nCAIn, nReCAIn, eCAIn, tCAIn);
                failureCnt = 0;
                while (failureCnt < 10) {
                    try {
                        BigInteger num = new BigInteger("11");
                        byte[] n = encodeBigIntegerArrayToEtherFormat(nIn);
                        byte[] nRe = encodeBigIntegerArrayToEtherFormat(nReIn);
                        byte[] vk = encodeBytesArrayToEtherFormat(Utils.fileToBytes("ethereumj-application-demo/res/VK_Maj_"+num));
                        byte[] ca_n = encodeBigIntegerArrayToEtherFormat(nCAIn);
                        byte[] ca_nRe = encodeBigIntegerArrayToEtherFormat(nReCAIn);
                        byte[] ca_vk = encodeBytesArrayToEtherFormat(Utils.fileToBytes("ethereumj-application-demo/res/VK_Certificate"));
                        logger.info("The " + (failureCnt + 1) + " trail to make initialization by calling 'init'");
                        CallTransaction.Function init = contract.getByName("init");
                        byte[] functionCallBytes =  encodeMultipleArgs(init, num, n, nRe, vk, ca_n, ca_nRe, ca_vk);
                        logger.info("Set up initial encryption parameters!");
                        long bonus = 667000000000010000L;
                        // //2_000_000_000_000
                        //700_000_000_000_000
                        receipt1 = sendTxAndWait(contractAddress, functionCallBytes,bonus,40_000_000L);
                        logger.info("Initial encryption parameters included!");
                        byte[] ret = receipt1.getExecutionResult();
                        if(ret != null) {
                            System.out.println("Deposit:");
                            //System.out.println(ret.length);
                            //System.out.println(Hex.toHexString(ret));
                            System.out.println(new BigInteger(ret));
                        }
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        //e.printStackTrace();
                        logger.info("Encryption parameters NOT packed!");
                        continue;
                    }
                }
            } // end of sending initialization parameters

            Thread.sleep(500);

            /**
             * 3. Collecting data
             */
            //3.1 Send the 1st data
            TransactionReceipt receipt2 = null;
            if (receipt1 != null) {
                //function submit_data(int256[] _enc_data)
                failureCnt = 0;
                String participant = participantsPrivateKeyStrings[0];
                while (failureCnt < 10) {
                    try {
                        logger.info("The " + (failureCnt + 1) + " trail to set data submission 0 by calling 'submit_data'");
                        byte[] token = encodeBigIntegerArrayToEtherFormat(tokens[0]);
                        byte[] proof = encodeBytesArrayToEtherFormat(Utils.fileToBytes("ethereumj-application-demo/res/Proof_0"));
                        byte[] submission = encodeBigIntegerArrayToEtherFormat(Utils.hexCipherTextTo32BigIntegers(cipherText[0]));
                        CallTransaction.Function submit = contract.getByName("submit_data");
                        //byte[] functionCallBytesPrefix = submit.encodeSignature();
                        byte[] functionCallBytes = encodeMultipleArgs(submit, token, proof, submission);
                        //byte[] functionCallBytes = merge(functionCallBytesPrefix, submission);
                        logger.info("Submit 0 data !");//2000000000000000
                        receipt2 = sendTxAndWait(participant, contractAddress, functionCallBytes,000L,3000000);
                        logger.info("The 0 data included!");
                        byte[] ret = receipt2.getExecutionResult();
                        System.out.println("Data /w token verification result:");
                        if (bytesToBigInteger(ret).intValue() == 1)
                            System.out.println("Data submitted with valid anonymous token!");
                        else {
                            System.out.println("Data rejected with invalid token!");
                            throw new RuntimeException("Data validation fails");
                        }
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        logger.info("Data 0 NOT packed!");
                        continue;
                    }
                }
            }
            Thread.sleep(500);
            //3.2 A malicious participant tries to double submit data
            boolean maliciousData = false;
            if (maliciousData) {
                receipt2 = null;
                if (receipt1 != null) {
                    //function submit_data(int256[] _enc_data)
                    failureCnt = 0;
                    String participant = participantsPrivateKeyStrings[0];
                    while (failureCnt < 10) {
                        try {
                            logger.info("The " + (failureCnt + 1) + " trail to set DUPLICATED data submission 0 by calling 'submit_data'");
                            byte[] token = encodeBigIntegerArrayToEtherFormat(tokens[0]);
                            byte[] proof = encodeBytesArrayToEtherFormat(Utils.fileToBytes("ethereumj-application-demo/res/Proof_0"));
                            byte[] submission = encodeBigIntegerArrayToEtherFormat(Utils.hexCipherTextTo32BigIntegers(cipherText[0]));
                            CallTransaction.Function submit = contract.getByName("submit_data");
                            //byte[] functionCallBytesPrefix = submit.encodeSignature();
                            byte[] functionCallBytes = encodeMultipleArgs(submit, token, proof, submission);
                            //byte[] functionCallBytes = merge(functionCallBytesPrefix, submission);
                            logger.info("Submit 0 data !");
                            receipt2 = sendTxAndWait(participant, contractAddress, functionCallBytes, 000L, 3000000);
                            logger.info("The 0 data included!");
                            byte[] ret = receipt2.getExecutionResult();
                            System.out.println("Data /w token verification result:");
                            if (bytesToBigInteger(ret).intValue() == 1)
                                System.out.println("Data is submitted with DUPLICATED token!");
                            else
                                System.out.println("Data is rejected with DUPLICATED token!");
                            break;
                        } catch (RuntimeException e) {
                            failureCnt++;
                            logger.info("Data 0 NOT packed!");
                            continue;
                        }
                    }
                }
                Thread.sleep(500);
            }
            //3.3 The other ten users send data
            final int dataNum = 11;
            int submissionCnt = 1;
            // function submit_data(int256[] _enc_data) {" +
            while (submissionCnt < dataNum) {
                String participant = participantsPrivateKeyStrings[submissionCnt];
                if (receipt1 != null) {
                    //function submit_data(int256[] _enc_data)
                    failureCnt = 0;
                    while (failureCnt < 10) {
                        try {
                            logger.info("The " + (failureCnt + 1) + " trail to set data submission " + submissionCnt + " by calling 'submit_data'");
                            byte[] token = encodeBigIntegerArrayToEtherFormat(tokens[submissionCnt]);
                            byte[] proof = encodeBytesArrayToEtherFormat(Utils.fileToBytes("ethereumj-application-demo/res/Proof_"+submissionCnt));
                            byte[] submission = encodeBigIntegerArrayToEtherFormat(Utils.hexCipherTextTo32BigIntegers(cipherText[submissionCnt]));
                            CallTransaction.Function submit = contract.getByName("submit_data");
                            //byte[] functionCallBytesPrefix = submit.encodeSignature();
                            byte[] functionCallBytes = encodeMultipleArgs(submit, token, proof, submission);
                            //byte[] functionCallBytes = merge(functionCallBytesPrefix, submission);
                            logger.info("Submit " + submissionCnt + " data !");
                            receipt2 = sendTxAndWait(participant, contractAddress, functionCallBytes,000L,3000000);
                            logger.info("The " + submissionCnt + " data included!");
                            byte[] ret = receipt2.getExecutionResult();
                            System.out.println("Data /w token verification result:");
                            if (bytesToBigInteger(ret).intValue() == 1)
                                System.out.println("Data submitted with valid anonymous token!");
                            else {
                                System.out.println("Data rejected with invalid token!");
                                throw new RuntimeException("Data validation fails");
                            }
                            submissionCnt++;
                            break;
                        } catch (RuntimeException e) {
                            failureCnt++;
                            logger.info("Data " + submissionCnt + " NOT packed!");
                            continue;
                        }
                    }
                }
                Thread.sleep(2000);
            }// end of sending legal data



            /**
             * 4. The owner of task sends majority's hash and a clue of how to pay bonus
             */
            TransactionReceipt verificationReceipt = null;
            //function end (int256 _majCount, int256[] _majDigest, int256[] _isMaj, int256[] _proof)
            if (receipt2 != null) {
                failureCnt = 0;
                while (failureCnt < 10) {
                    //Thread.sleep(1000);
                    try {
                        byte[] digest = encodeBigIntegerArrayToEtherFormat(Utils.hexDigestTo8BigIntegers(majDigest));
                        byte[] isMajVector = encodeBigIntegerArrayToEtherFormat(isMaj);
                        byte[] proof = encodeBytesArrayToEtherFormat(Utils.fileToBytes("ethereumj-application-demo/res/Proof_Maj_11"));
                        logger.info("The " + (failureCnt + 1) + " trail to end task by calling 'end'");
                        CallTransaction.Function end = contract.getByName("end");

                        byte[] functionCallBytes = encodeMultipleArgs(end, majCount, digest, isMajVector, proof);
                        logger.info("Do verification request!");
                        verificationReceipt = sendTxAndWait(contractAddress, functionCallBytes,000L,50_000_000_000L);
                        logger.info("Verification result received!");

                        byte[] ret = verificationReceipt.getExecutionResult();
                        System.out.println("Majority verification result:");
                        //System.out.println(bytesToBigInteger(ret).toString());
                        if (bytesToBigInteger(ret).intValue() == 200)
                            System.out.println("Majority verification Passed; Deposit can be refunded after bonus honored!");
                        else
                            System.out.println("Majority verification Failed; Deposit can NOT be refunded!");
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        logger.info("Verifying Request NOT packed!");
                        continue;
                    }
                }
            } // end of sending proof and confirm verification
            Thread.sleep(500);

            /**
             * 5. Honor bonus to participants
             */
            TransactionReceipt fundBonusReceipt = null;
            //function end (int256 _majCount, int256[] _majDigest, int256[] _isMaj, int256[] _proof)
            if (verificationReceipt != null) {
                failureCnt = 0;
                while (failureCnt < 10) {
                    //Thread.sleep(1000);
                    try {
                        logger.info("The " + (failureCnt + 1) + " trail to fund bonus by calling 'fund_bonus'");
                        CallTransaction.Function fundBonus = contract.getByName("fund_bonus");
                        byte[] functionCallBytes = fundBonus.encode();
                        logger.info("Do fund bonus request!");
                        fundBonusReceipt = sendTxAndWait(contractAddress, functionCallBytes,0L,300_000_000L);
                        logger.info("Fund bonus received!");

                        byte[] ret = fundBonusReceipt.getExecutionResult();
                        System.out.println("Remaining balance after honoring bonus:");
                        System.out.println(bytesToBigInteger(ret).toString());
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        logger.info("Fund bonus Request NOT packed!");
                        continue;
                    }
                }
            } // end of sending proof and confirm verification
            Thread.sleep(500);

            //Thread.sleep(1000);

            /**
             * 6. The owner gets deposit back
             */
            TransactionReceipt refundDepositReceipt = null;
            //function end (int256 _majCount, int256[] _majDigest, int256[] _isMaj, int256[] _proof)
            if (fundBonusReceipt != null) {
                failureCnt = 0;
                while (failureCnt < 10) {
                    //Thread.sleep(1000);
                    try {
                        logger.info("The " + (failureCnt + 1) + " trail to refund deposit by calling 'refund_deposit'");
                        CallTransaction.Function refundDeposit = contract.getByName("refund_deposit");
                        byte[] functionCallBytes = refundDeposit.encode();
                        logger.info("Do refund deposit request!");
                        refundDepositReceipt = sendTxAndWait(contractAddress, functionCallBytes,0L,500_000L);
                        logger.info("Refund deposit received!");

                        byte[] ret = refundDepositReceipt.getExecutionResult();
                        System.out.println("Remaining balance after refunding deposit:");
                        System.out.println(bytesToBigInteger(ret).toString());
                        break;
                    } catch (RuntimeException e) {
                        failureCnt++;
                        logger.info("Fund bonus Request NOT packed!");
                        continue;
                    }
                }
            } // end of sending proof and confirm verification
            Thread.sleep(500);





//            /**
//             * 7. Kill contract
//             */
//            //TransactionReceipt refundDepositReceipt;
//            //function end (int256 _majCount, int256[] _majDigest, int256[] _isMaj, int256[] _proof)
//            if (refundDepositReceipt != null) {
//                failureCnt = 0;
//                while (failureCnt < 10) {
//                    //Thread.sleep(1000);
//                    try {
//                        logger.info("The " + (failureCnt + 1) + " trail to refund deposit by calling 'kill'");
//                        CallTransaction.Function kill = contract.getByName("kill");
//                        byte[] functionCallBytes = kill.encode();
//                        logger.info("Do kill request!");
//                        sendTxAndWait(contractAddress, functionCallBytes,0L,100_000L);
//                        logger.info("Kill received!");
//                        break;
//                    } catch (RuntimeException e) {
//                        failureCnt++;
//                        logger.info("Kill Request NOT packed!");
//                        continue;
//                    }
//                }
//            } // end of sending proof and confirm verification
//            Thread.sleep(500);

            BigInteger[] finalBalances = new BigInteger[12];
            System.out.println("Final balances:");
            finalBalances[0] = ethereum.getRepository().getBalance(fromAddress);
            System.out.println(finalBalances[0]);
            for(int i = 0; i < 11; i++) {
                String participant = participantsPrivateKeyStrings[i];
                byte[] participantPrivateKey = Hex.decode(participant);
                byte[] participantAddress = ECKey.fromPrivate(participantPrivateKey).getAddress();
                finalBalances[i+1] = ethereum.getRepository().getBalance(participantAddress);
                System.out.println(finalBalances[i+1]);
            }

            System.out.println("Balances change:");
            for(int i = 0; i < 12; i++) {
                System.out.println(finalBalances[i].subtract(initialBalances[i]));
            }

//            BigInteger finalBalance = ethereum.getRepository().getBalance(fromAddress);
//            System.out.println("Final balance:");
//            System.out.println(finalBalance);
        } // end of onSyncDone method


        protected TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data) throws RuntimeException,InterruptedException {
            return sendTxAndWait(receiveAddress, data, 0x0L,50_000_000L);
        }

        protected TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data, long value) throws RuntimeException,InterruptedException {
            return sendTxAndWait(receiveAddress, data, value,50_000_000L);
        }

        protected TransactionReceipt sendTxAndWait(byte[] receiveAddress, byte[] data, long value, long gas) throws RuntimeException,InterruptedException {
            BigInteger nonce = ethereum.getRepository().getNonce(senderAddress);
            logger.info("<=== Sending data: " + Hex.toHexString(data));
            Transaction tx = new Transaction(
                    bigIntegerToBytes(nonce),
                    //ByteUtil.longToBytesNoLeadZeroes(1 * ethereum.getGasPrice() / 1024),
                    ByteUtil.longToBytesNoLeadZeroes(20000000L),
                    ByteUtil.longToBytesNoLeadZeroes(gas),
                    receiveAddress,
                    ByteUtil.longToBytesNoLeadZeroes(value),
                    data,
                    ethereum.getChainIdForNextBlock());
            tx.sign(ECKey.fromPrivate(senderPrivateKey));
            logger.info("<=== Sending transaction: " + tx);
            ethereum.submitTransaction(tx);
            logger.info("<=== Balance of sender: " + ethereum.getRepository().getBalance(senderAddress));
            logger.info("<=== Hash of transaction: " + Hex.toHexString(tx.getHash()));
            return waitForTx(tx.getHash());
        }

        protected TransactionReceipt sendTxAndWait(String senderPrivateKeyString, byte[] receiveAddress, byte[] data, long value, long gas) throws RuntimeException,InterruptedException {
            byte[] participantPrivateKey = Hex.decode(senderPrivateKeyString);
            byte[] participantAddress = ECKey.fromPrivate(participantPrivateKey).getAddress();
            BigInteger nonce = ethereum.getRepository().getNonce(participantAddress);
            logger.info("<=== Sending data: " + Hex.toHexString(data));
            Transaction tx = new Transaction(
                    bigIntegerToBytes(nonce),
                    //ByteUtil.longToBytesNoLeadZeroes(1 * ethereum.getGasPrice() / 1024),
                    ByteUtil.longToBytesNoLeadZeroes(22145659410L), //2017 April 1st gasPrice
                    ByteUtil.longToBytesNoLeadZeroes(gas),
                    receiveAddress,
                    ByteUtil.longToBytesNoLeadZeroes(value),
                    data,
                    ethereum.getChainIdForNextBlock());
            tx.sign(ECKey.fromPrivate(participantPrivateKey));
            logger.info("<=== Sending transaction: " + tx);
            ethereum.submitTransaction(tx);
            logger.info("<=== Balance of participant: " + ethereum.getRepository().getBalance(participantAddress));
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
            byte[] senderPrivateKey = Hex.decode("c940ad1df4aafcb7e30139429d1577dee8ef90498eec5403f379a7a223338505");
            byte[] fromAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();
        }

        final int BLOCK_NUM_FOR_RESEND = 6;
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
                        "    { url = 'enode://7ee4d7e0a45fcb040b215ed4f842b129e8d7b2e715fafa009a8908044a57b3c1015659b199c3047f47b77c901b35e13b9a42eaa2a5fc6e87ad3764afc2b98682@127.0.0.1:33333' }," +
                        "    { url = 'enode://466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a@127.0.0.1:30002' }" +
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
                        "cache.flush.blocks = 1";

        @Bean
        public SnarkVerifyElevenPlayersMajority.MinerNode1 node() {
            return new SnarkVerifyElevenPlayersMajority.MinerNode1();
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
                    SnarkVerifyElevenPlayersMajority.MinerNode1.this.onBlock(block, receipts);
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
                if (balance.compareTo(new BigInteger("1000000000000000000000000000000")) == 1 && txWaiters.isEmpty()) {
                    Transaction tx = new Transaction(
                            ByteUtil.bigIntegerToBytes(nonce),
                            ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice() / 1024),
                            ByteUtil.longToBytesNoLeadZeroes(100_000L),
                            toAddress,
                            ByteUtil.bigIntegerToBytes(balance.subtract(new BigInteger("10000000"))), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                            data,
                            ethereum.getChainIdForNextBlock());
                    tx.sign(ECKey.fromPrivate(senderPrivateKey));
                    //logger.info("<=== Sending transaction: " + tx);
                    ethereum.submitTransaction(tx);
                    try {
                        waitForTx(tx.getHash());
                        //logger.info("Transaction INCLUDED!");
                    } catch (Exception e) {
                        txWaiters.clear();
                        //logger.info("Transaction NOT packed.");
                        //e.printStackTrace();
                    }
                }
            }

//            synchronized (this) {
//                try {
//                    wait(777);
//                } catch (InterruptedException e) {
//                    e.printStackTrace();
//                }
//            }

            flag = 0;
        }

        @Override
        public void blockMiningCanceled(Block block) {
            //logger.info("Miner " + number + " cancels mining block: " + block.getShortDescr());
        }

        boolean waiting = true;
        private TransactionReceipt waitForTx(byte[] txHash) throws InterruptedException,RuntimeException {
            ByteArrayWrapper txHashW = new ByteArrayWrapper(txHash);
            txWaiters.put(txHashW, null);
            long startBlock = ethereum.getBlockchain().getBestBlock().getNumber();

            Timer timer = new Timer();
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    waiting = false;
                }
            },30_000L);

            while(waiting) {
                TransactionReceipt receipt = txWaiters.get(txHashW);
                if (receipt != null) {
                    txWaiters.remove(txHashW);
                    return receipt;
                } else {
                    long curBlock = ethereum.getBlockchain().getBestBlock().getNumber();
                    if (curBlock > startBlock + 6) {
                        txWaiters.remove(txHashW);
                        throw new RuntimeException("Transaction was NOT included last 6 blocks: " + txHashW.toString().substring(0,8));
                    } else {
                        //logger.info("Waiting for block with transaction 0x" + txHashW.toString().substring(0,8) +
                        //        " packed (" + (curBlock - startBlock) + " blocks received so far) ...");
                    }
                }
                synchronized (this) {
                    wait(555);
                }
            }
            waiting = true;
            throw new RuntimeException("Transaction was NOT included last 30 seconds " + txHashW.toString().substring(0,8));
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
                        "    { url = 'enode://4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1@127.0.0.1:30001' }," +
                        "    { url = 'enode://7ee4d7e0a45fcb040b215ed4f842b129e8d7b2e715fafa009a8908044a57b3c1015659b199c3047f47b77c901b35e13b9a42eaa2a5fc6e87ad3764afc2b98682@127.0.0.1:33333' }" +
                        "] \n" +
                        // we have no peers to sync with
                        "sync.enabled = true \n" +
                        // genesis with a lower initial difficulty and some predefined known funded accounts
                        "genesis = genesis.json \n" +
                        // two peers need to have separate database dirs
                        "database.dir = miner-2 \n" +
                        // when more than 1 miner exist on the network extraData helps to identify the block creator
                        "mine.extraDataHex = cccccccccccccccccccc \n" +
                        "mine.cpuMineThreads = 2 \n" +
                        "mine.coinbase = 1563915e194d8cfba1943570603f7606a3115508 \n" +
                        "cache.flush.blocks = 1";

        @Bean
        public SnarkVerifyElevenPlayersMajority.MinerNode2 node() {
            return new SnarkVerifyElevenPlayersMajority.MinerNode2();
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
                logger.info("0");
                ethash.getFullDataset();
                logger.info("Full dataset generated (loaded).");
            }
            logger.info("Miner " + number + " nodeID: " + bytesToBigInteger(config.nodeId()).toString(16));
            ethereum.addListener(new EthereumListenerAdapter() {
                // when block arrives look for our included transactions
                @Override
                public void onBlock(Block block, List<TransactionReceipt> receipts) {
                    SnarkVerifyElevenPlayersMajority.MinerNode2.this.onBlock(block, receipts);
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
                if (balance.compareTo(new BigInteger("2000000000000000000000000000000")) == 1 && txWaiters.isEmpty()) {
                    Transaction tx = new Transaction(
                            ByteUtil.bigIntegerToBytes(nonce),
                            ByteUtil.longToBytesNoLeadZeroes(ethereum.getGasPrice() / 1024),
                            ByteUtil.longToBytesNoLeadZeroes(150_000L),
                            toAddress,
                            ByteUtil.bigIntegerToBytes(balance.subtract(new BigInteger("10000000"))), //1_000_000_000 gwei, 1_000_000_000_000L szabo, 1_000_000_000_000_000L finney, 1_000_000_000_000_000_000L ether
                            data,
                            ethereum.getChainIdForNextBlock());
                    tx.sign(ECKey.fromPrivate(senderPrivateKey));
                    //logger.info("<=== Sending transaction: " + tx);
                    ethereum.submitTransaction(tx);
                    try {
                        waitForTx(tx.getHash());
                        //logger.info("Transaction INCLUDED!");
                    } catch (Exception e) {
                        txWaiters.clear();
                        //logger.info("Transaction NOT packed.");
                        //e.printStackTrace();
                    }
                }
            }
            //reset semaphore

//            synchronized (this) {
//                try {
//                    wait(20000);
//                } catch (InterruptedException e) {
//                    e.printStackTrace();
//                }
//            }

            flag = 0;
        }

        @Override
        public void blockMiningCanceled(Block block) {
            //logger.info("Miner " + num + " cancels mining block: " + block.getShortDescr());
        }

        boolean waiting = true;
        private TransactionReceipt waitForTx(byte[] txHash) throws InterruptedException,RuntimeException {
            ByteArrayWrapper txHashW = new ByteArrayWrapper(txHash);
            txWaiters.put(txHashW, null);
            long startBlock = ethereum.getBlockchain().getBestBlock().getNumber();

            Timer timer = new Timer();
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    waiting = false;
                }
            },30_000L);

            while(waiting) {
                TransactionReceipt receipt = txWaiters.get(txHashW);
                if (receipt != null) {
                    txWaiters.remove(txHashW);
                    return receipt;
                } else {
                    long curBlock = ethereum.getBlockchain().getBestBlock().getNumber();
                    if (curBlock > startBlock + 6) {
                        txWaiters.remove(txHashW);
                        throw new RuntimeException("Transaction NOT included in 6 blocks: " + txHashW.toString().substring(0,8));
                    } else {
                        //logger.info("Waiting for block with transaction 0x" + txHashW.toString().substring(0,8) +
                        //        " packed (" + (curBlock - startBlock) + " blocks received so far) ...");
                    }
                }
                synchronized (this) {
                    wait(2000);
                }
            }
            waiting = true;
            throw new RuntimeException("Transaction NOT included in 30 seconds: " + txHashW.toString().substring(0,8));
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
        Ethereum peer = EthereumFactory.createEthereum(SnarkVerifyElevenPlayersMajority.RegularPeerConfig.class);
        //peer.getBlockMiner().startMining();


        BasicSample.sLogger.info("Starting EthtereumJ miner 1 instance!");
        Ethereum miner1 = EthereumFactory.createEthereum(SnarkVerifyElevenPlayersMajority.MinerConfig1.class);
        //miner1.getBlockMiner().stopMining();
        //miner1.getBlockMiner().startMining();
        //miner1.getBlockMiner().stopMining();

        BasicSample.sLogger.info("Starting EthtereumJ miner 2 instance!");
        Ethereum miner2 = EthereumFactory.createEthereum(SnarkVerifyElevenPlayersMajority.MinerConfig2.class);
        //miner2.getBlockMiner().startMining();
        //miner2.getBlockMiner().stopMining();
    }





}
