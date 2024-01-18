pragma circom  2.1.2;
include "../../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

include "../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "./circom-ecsda/ecdsa.circom";
include "./circom-ecsda/zk-identity/eth.circom";

//该template的目的是实现带有谓词predicate的凭证验证
//目前只实现了四个谓词：bigger:[0,0],less:[0,1],in:[1,0],notin:[1,1]

template VerifyCertificate(DID_level,ID_level){
    //public signal------------------------
    signal input DIDRoot;
    signal input HashedIDRoot;
    signal input SIG_issuer[3];
    signal input PK_issuer[2];
    signal input DIDv;
    signal input SIG_Downer[3];

    //private signal------------------------
    signal input id_claim;
    signal input DIDu;
    signal input ID;
    signal input Salt;
    signal input Owner;
    signal input SK_Owner[4];
    // signal input PK_Owner[2]; 此处为论文中的描述。但由于电脑配置不够，在circom里算不了secp256k1的签名验证，此处注释
    // signal input SIG_Owner[3];
    signal input PK_Downer[2];
    signal input EnigmaRoot;
    signal input DID_MKT_Proof[DID_level];
    signal input HashedID_MKT_Proof[ID_level];
    signal input attribute_withoutDID;
    // signal input HashedID_Key;//SMT的key
    // signal input DID_Key;//SMT的key


    
    //构建DID树的叶子
    component DID_leaf_hash = Poseidon(5);
    DID_leaf_hash.inputs[0] <== DIDu;
    DID_leaf_hash.inputs[1] <== ID;
    DID_leaf_hash.inputs[2] <== Salt;
    DID_leaf_hash.inputs[3] <== PK_Downer[0];
    DID_leaf_hash.inputs[4] <== PK_Downer[1];
    log("DID_leaf_hash.out",DID_leaf_hash.out);


    //构建HashedID
    component hash=Poseidon(1);
    hash.inputs[0] <== ID;//F.e(ID)
    component hashSalt=Poseidon(2);
    hashSalt.inputs[0] <== hash.out;
    hashSalt.inputs[1] <== Salt;
    log("HashedID",hashSalt.out);

    //构建HashedID树的叶子
    component HashedID_leaf_hash = Poseidon(3);
    HashedID_leaf_hash.inputs[0] <== hashSalt.out;
    HashedID_leaf_hash.inputs[1] <== Owner;
    HashedID_leaf_hash.inputs[2] <== EnigmaRoot;
    log("HashedID_leaf_hash.out",HashedID_leaf_hash.out);

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

    

    component SIG_Verifier[3];
    //验证issuer对属性+DIDu的签名
    SIG_Verifier[0]=EdDSAPoseidonVerifier();
    SIG_Verifier[0].enabled <== 1;
    SIG_Verifier[0].Ax <== PK_issuer[0];
    SIG_Verifier[0].Ay <== PK_issuer[1];
    SIG_Verifier[0].R8x <== SIG_issuer[0];
    SIG_Verifier[0].R8y <== SIG_issuer[1];
    SIG_Verifier[0].S <== SIG_issuer[2];
    SIG_Verifier[0].M <== id_claim + attribute_withoutDID + DIDu;
    


    //验证Owner对DIDu的签名
    

    //验证Downer对“属性+DIDu+DIDv”的签名
    SIG_Verifier[2]=EdDSAPoseidonVerifier();
    SIG_Verifier[2].enabled <== 1;
    SIG_Verifier[2].Ax <== PK_Downer[0];
    SIG_Verifier[2].Ay <== PK_Downer[1];
    SIG_Verifier[2].R8x <== SIG_Downer[0];
    SIG_Verifier[2].R8y <== SIG_Downer[1];
    SIG_Verifier[2].S <== SIG_Downer[2];
    SIG_Verifier[2].M <== id_claim + attribute_withoutDID + DIDu + DIDv;

    //验证持有Owner的私钥
    //从Owner的私钥生成Owner的公钥
    component privToPub_Owner = ECDSAPrivToPub(64, 4);
    //从Downer的私钥生成Owner的公钥
    for (var i = 0; i < 4; i++) {
        privToPub_Owner.privkey[i] <== SK_Owner[i];
    }
    //验证私钥来自Owner和Downer
    component flattenPub;
    flattenPub = FlattenPubkey(64, 4);
    for (var i = 0; i < 4; i++) {
        flattenPub.chunkedPubkey[0][i] <== privToPub_Owner.pubkey[0][i];
        flattenPub.chunkedPubkey[1][i] <== privToPub_Owner.pubkey[1][i];
    }
    component pubToAddr;
    pubToAddr = PubkeyToAddress();
    for (var i = 0; i < 512; i++) {
        pubToAddr.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    }
    Owner === pubToAddr.address;
    


    
    
}

component main{public [ DIDRoot,HashedIDRoot,SIG_issuer,PK_issuer,DIDv,SIG_Downer ] } = VerifyCertificate(3,3);
