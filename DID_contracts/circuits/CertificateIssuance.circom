pragma circom  2.1.2;
include "../../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/smt/smtverifier.circom";
// include "./circom-ecsda/ecdsa.circom";
// include "./circom-ecsda/zk-identity/eth.circom";

// 我所知道最快证明Ecdsa签名的circom是spartan-ecdsa，但它的签名验证方法不以msg作为输入，所以本文只能使用较臃肿的circom-ecdsa进行开发
// 以下签名验证应该使用secp256k1曲线的签名，但是我电脑带不动这个约束的量级，就换成了poseidon的签名
//  //从Owner的私钥生成Owner的公钥
//     component privToPub_Owner = ECDSAPrivToPub(64, 4);
//     //从Downer的私钥生成Owner的公钥
//     component privToPub_Downer = ECDSAPrivToPub(64, 4);
//     for (var i = 0; i < 4; i++) {
//         privToPub_Owner.privkey[i] <== SK_Owner[i];
//         privToPub_Downer.privkey[i] <== SK_Downer[i];
//     }

//     //验证私钥来自Owner和Downer
//     component flattenPub[2];
//     flattenPub[0] = FlattenPubkey(64, 4);
//     flattenPub[1] = FlattenPubkey(64, 4);
//     for (var i = 0; i < 4; i++) {
//         flattenPub[0].chunkedPubkey[0][i] <== privToPub_Owner.pubkey[0][i];
//         flattenPub[0].chunkedPubkey[1][i] <== privToPub_Owner.pubkey[1][i];
//         flattenPub[1].chunkedPubkey[0][i] <== privToPub_Downer.pubkey[0][i];
//         flattenPub[1].chunkedPubkey[1][i] <== privToPub_Downer.pubkey[1][i];
//     }
//     component pubToAddr[2];
//     pubToAddr[0] = PubkeyToAddress();
//     pubToAddr[1] = PubkeyToAddress();
//     for (var i = 0; i < 512; i++) {
//         pubToAddr[0].pubkeyBits[i] <== flattenPub[0].pubkeyBits[i];
//         pubToAddr[1].pubkeyBits[i] <== flattenPub[1].pubkeyBits[i];
//     }
//     Owner === pubToAddr[0].address;
//     Old_Downer === pubToAddr[1].address;


template CertificateIssuance(DID_level,ID_level){
    //public signal
    signal input DIDRoot;
    signal input HashedIDRoot;

    //private signal
    signal input DIDu;
    signal input ID;
    signal input Salt;
    signal input PK_Owner[2];// signal input SK_Owner;这里也该用上面的secp256k1曲线的私钥来生成公钥，但为了保护我的电脑风扇，直接换成poseidon的公钥了。领会精神即可。
    signal input PK_Downer[2];
    signal input SIG_Owner[3];// 签名验证应该使用secp256k1曲线的签名，但是我电脑带不动就换了poseidon的签名，领会精神即可
    signal input SIG_Downer[3];
    signal input EnigmaRoot;
    signal input DID_MKT_Proof[DID_level];
    signal input HashedID_MKT_Proof[ID_level];
    signal input HashedID_Key;//SMT的key
    signal input DID_Key;//SMT的key

    


    //构建DID树的叶子
    component DID_leaf_hash = Poseidon(5);
    DID_leaf_hash.inputs[0] <== DIDu;
    DID_leaf_hash.inputs[1] <== ID;
    DID_leaf_hash.inputs[2] <== Salt;
    DID_leaf_hash.inputs[3] <== PK_Downer[0];
    DID_leaf_hash.inputs[4] <== PK_Downer[1];


    //构建HashedID
    component hash=Poseidon(1);
    hash.inputs[0] <== ID;//F.e(ID)
    component hashSalt=Poseidon(2);
    hashSalt.inputs[0] <== hash.out;
    hashSalt.inputs[1] <== Salt;

    //构建HashedID树的叶子
    component HashedID_leaf_hash = Poseidon(4);
    HashedID_leaf_hash.inputs[0] <== hashSalt.out;
    HashedID_leaf_hash.inputs[1] <== PK_Owner[0];
    HashedID_leaf_hash.inputs[2] <== PK_Owner[1];
    HashedID_leaf_hash.inputs[3] <== EnigmaRoot;

    //验证所构建DID树的叶子是否存在于DID树中
    component DIDtree_verify = SMTVerifier(DID_level);//26
    DIDtree_verify.enabled <== 1;
    DIDtree_verify.fnc <== 0;
    DIDtree_verify.root <== DIDRoot;
    DIDtree_verify.siblings <== DID_MKT_Proof;
    DIDtree_verify.oldKey <== 0;
    DIDtree_verify.oldValue <== 0;
    DIDtree_verify.isOld0 <== 0;
    DIDtree_verify.key <== 3;//随便写的
    DIDtree_verify.value <== DID_leaf_hash.out;

    //验证所构建HashedID树的叶子是否存在于HashedID树中
    component HashedIDtree_verify = SMTVerifier(ID_level);//26
    HashedIDtree_verify.enabled <== 1;
    HashedIDtree_verify.fnc <== 0;
    HashedIDtree_verify.root <== HashedIDRoot;
    HashedIDtree_verify.siblings <== HashedID_MKT_Proof;
    HashedIDtree_verify.oldKey <== 0;
    HashedIDtree_verify.oldValue <== 0;
    HashedIDtree_verify.isOld0 <== 0;
    HashedIDtree_verify.key <== 3;//随便写的
    HashedIDtree_verify.value <== HashedID_leaf_hash.out;

     //验证Owner对Downer的签名
    component SIG_Verifier[2];
    SIG_Verifier[0]=EdDSAPoseidonVerifier();
    SIG_Verifier[0].enabled <== 1;
    SIG_Verifier[0].Ax <== PK_Owner[0];
    SIG_Verifier[0].Ay <== PK_Owner[1];
    SIG_Verifier[0].R8x <== SIG_Owner[0];
    SIG_Verifier[0].R8y <== SIG_Owner[1];
    SIG_Verifier[0].S <== SIG_Owner[2];
    SIG_Verifier[0].M <== PK_Downer[0] + PK_Downer[1];

    //验证用户确实持有新的Downer私钥
    SIG_Verifier[1]=EdDSAPoseidonVerifier();
    SIG_Verifier[1].enabled <== 1;
    SIG_Verifier[1].Ax <== PK_Downer[0];
    SIG_Verifier[1].Ay <== PK_Downer[1];
    SIG_Verifier[1].R8x <== SIG_Downer[0];
    SIG_Verifier[1].R8y <== SIG_Downer[1];
    SIG_Verifier[1].S <== SIG_Downer[2];
    SIG_Verifier[1].M <== hashSalt.out;//+time  防止replay，在合约里也要防止replay

}

component main{public [ DIDRoot,HashedIDRoot] } = CertificateIssuance(3,3);
