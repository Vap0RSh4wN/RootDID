pragma circom  2.1.2;
include "../../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/mux2.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

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
    //谓词predicate
    signal input predicate[2];//bigger:[0,0],less:[0,1],in:[1,0],notin:[1,1]
    signal input Comparison_object;//公开的比较对象
    signal input in_or_notin[3];//这里为了展示时少点约束调小了，正常时候可以调大点
    signal input enable_sybli_value;//是否设置sybli_value的开关，0为关闭，1为开启
    signal input sybli_value;//由验证者提供的随机值，抗女巫。enable_sybli_value为0时sybli_value也需设置为0

    //private signal------------------------
    signal input predicate_object; //私有输入的要证明的属性
    signal input id_claim;
    signal input DIDu;
    signal input ID;
    signal input Salt;
    signal input Owner;
    signal input SK_Owner[4];
    // signal input PK_Owner[2]; 我的电脑配置不够，在circom里算不了secp256k1的签名验证
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
    

    //谓词检测
    //不设置等于，当希望大于等于18时可以直接设为大于17
    component bigger = GreaterThan(64); //0 (meaning input[0] < input[1]) or 1 (meaning input[0] > input[1])
    component less = LessThan(64); //0 (meaning input[0] > input[1]) or 1 (meaning input[0] < input[1])
    //predicate is bigger, predicate > Comparison_object
    bigger.in[0] <== predicate_object;
    bigger.in[1] <== Comparison_object;
    //predicate is less, predicate < Comparison_object
    less.in[0] <== predicate_object;
    less.in[1] <== Comparison_object;

    var in = 0;
    var notin = 1;

    component equal[3]; // 1是相等，0是不等
    for (var i = 0; i < 3; i++) {
        equal[i] = IsEqual();
        equal[i].in[0] <== predicate_object;
        equal[i].in[1] <== in_or_notin[i];
        in = in + equal[i].out;
        notin = notin + equal[i].out;
    }
    //sum>=1说明 in ，sum==0说明not in（这里就省略前者>1的可能，直接==1吧）

    component selector = Mux2();
    selector.c[0] <== bigger.out;
    selector.c[1] <== less.out;
    selector.c[2] <== in;
    selector.c[3] <== notin;
    selector.s <== predicate;
    selector.out === 1;


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
    

    //生成抗女巫攻击的human值
    
    component HID = Poseidon(1);
    HID.inputs[0] <== ID;
    component human = Poseidon(3);
    human.inputs[0] <== HID.out;
    human.inputs[1] <== Salt;
    human.inputs[2] <== attribute_withoutDID;
    sybli_value === human.out * enable_sybli_value;
    
    
}

component main{public [ DIDRoot,HashedIDRoot,SIG_issuer,PK_issuer,DIDv,SIG_Downer,predicate,Comparison_object,in_or_notin,enable_sybli_value,sybli_value ] } = VerifyCertificate(3,3);
