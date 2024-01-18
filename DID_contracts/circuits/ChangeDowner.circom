pragma circom  2.0.6;
include "../../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../../node_modules/circomlib/circuits/smt/smtverifier.circom";
// include "./circom-ecsda/ecdsa.circom";
// include "./circom-ecsda/zk-identity/eth.circom";

// 我所知道最快证明Ecdsa签名的circom是spartan-ecdsa，但它的签名验证方法不以msg作为输入，所以本文只能使用较臃肿的circom-ecdsa进行开发
// 以下签名验证应该使用secp256k1曲线的签名，但是我电脑带不动就换了poseidon的签名，领会精神即可

//验证Owner对new Downer的签名
    // component SIG_Verifier = ECDSAVerifyNoPubkeyCheck(64,4);
    // component msg_New_Downer = BigIntToArray(64, 4);
    // msg_New_Downer.in <== New_Downer;
    // for(var i=0;i<4;i++){
    //     SIG_Verifier.r[i] <== SIG_Owner[i];
    //     SIG_Verifier.s[i] <== SIG_Owner[i+4];
    //     SIG_Verifier.msghash[i] <== msg_New_Downer.out[i];
    //     SIG_Verifier.pubkey[0][i] <== privToPub_Owner.pubkey[0][i];
    //     SIG_Verifier.pubkey[1][i] <== privToPub_Owner.pubkey[1][i];//public
    // }

    // //验证私钥来自Owner
    // component flattenPub = FlattenPubkey(64, 4);
    // for (var i = 0; i < 4; i++) {
    //     flattenPub.chunkedPubkey[0][i] <== privToPub_Owner.pubkey[0][i];
    //     flattenPub.chunkedPubkey[1][i] <== privToPub_Owner.pubkey[1][i];
    // }
    // component pubToAddr = PubkeyToAddress();
    // for (var i = 0; i < 512; i++) {
    //     pubToAddr.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    // }
    // Owner === pubToAddr.address;


template SplitNumber() {
    signal input in;
    signal output firstHalfBits;
    signal output secondHalfBits;

    component n2b = Num2Bits(256);
    n2b.in <== in;

    component b2n1 = Bits2Num(128);
    component b2n2 = Bits2Num(128);

    for (var i = 0; i < 128; i++) {
        b2n1.in[i] <== n2b.out[i];
        b2n2.in[i] <== n2b.out[i+128];
    }

    firstHalfBits <== b2n1.out;
    secondHalfBits <== b2n2.out;
}

template PrivToPubKey() {
    // Needs to be hashed, and then pruned before supplying it to the circuit
    signal input privKey;
    signal output pubKey[2];

    component privBits = Num2Bits(253);
    privBits.in <== privKey;

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component mulFix = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i++) {
        mulFix.e[i] <== privBits.out[i];
    }

    pubKey[0] <== mulFix.out[0];
    pubKey[1] <== mulFix.out[1];
}

template RootContrust(){
        //private signal
    signal input SIG0[3];
    signal input SIG1[3];
    signal input ID;
    signal input Salt;
    signal input PrivKey0;
    signal input PrivKey1;
    signal input order[24];

    signal output Root;

    signal PubKey[4];

    //generate public keys from two private keys
    component privToPubKey[2];
    privToPubKey[0] = PrivToPubKey();
    privToPubKey[0].privKey <== PrivKey0;
    PubKey[0] <== privToPubKey[0].pubKey[0];
    PubKey[1] <== privToPubKey[0].pubKey[1];
    privToPubKey[1] = PrivToPubKey();
    privToPubKey[1].privKey <== PrivKey1;
    PubKey[2] <== privToPubKey[1].pubKey[0];
    PubKey[3] <== privToPubKey[1].pubKey[1];
    log("PubKey[0]:",PubKey[0],"PubKey[1]:",PubKey[1],"PubKey[2]:",PubKey[2],"PubKey[3]:",PubKey[3]);

    //check if the two signatures are valid
    component SIG_Verifier[2];
    SIG_Verifier[0]=EdDSAPoseidonVerifier();
    SIG_Verifier[0].enabled <== 1;
    SIG_Verifier[0].Ax <== PubKey[0];
    SIG_Verifier[0].Ay <== PubKey[1];
    SIG_Verifier[0].R8x <== SIG0[0];
    SIG_Verifier[0].R8y <== SIG0[1];
    SIG_Verifier[0].S <== SIG0[2];
    SIG_Verifier[0].M <== ID;
    SIG_Verifier[1]=EdDSAPoseidonVerifier();
    SIG_Verifier[1].enabled <== 1;
    SIG_Verifier[1].Ax <== PubKey[2];
    SIG_Verifier[1].Ay <== PubKey[3];
    SIG_Verifier[1].R8x <== SIG1[0];
    SIG_Verifier[1].R8y <== SIG1[1];
    SIG_Verifier[1].S <== SIG1[2];
    SIG_Verifier[1].M <== ID;
    log("signature0.R8[0]",SIG0[0],"signature0.R8[1]",SIG0[1],"signature0.S",SIG0[2]);
    log("signature1.R8[0]",SIG1[0],"signature1.R8[1]",SIG1[1],"signature1.S",SIG1[2]);


    var leafpieces[24];
    signal leaf[4];

    component Split[12];
    Split[0]=SplitNumber();
    Split[0].in <== SIG0[0];
    Split[1]=SplitNumber();
    Split[1].in <== SIG0[1];
    Split[2]=SplitNumber();
    Split[2].in <== SIG0[2];
    Split[3]=SplitNumber();
    Split[3].in <== SIG1[0];
    Split[4]=SplitNumber();
    Split[4].in <== SIG1[1];
    Split[5]=SplitNumber();
    Split[5].in <== SIG1[2];
    Split[6]=SplitNumber();
    Split[6].in <== PubKey[0];
    Split[7]=SplitNumber();
    Split[7].in <== PubKey[1];
    Split[8]=SplitNumber();
    Split[8].in <== PubKey[2];
    Split[9]=SplitNumber();
    Split[9].in <== PubKey[3];
    Split[10]=SplitNumber();
    Split[10].in <== PrivKey0;
    Split[11]=SplitNumber();
    Split[11].in <== PrivKey1;

    var j=0;
    for(var i=0;i<24;i=i+2){
        leafpieces[order[i]] = Split[j].secondHalfBits;
        leafpieces[order[i+1]] = Split[j].firstHalfBits;
        j++;
        log("leafpieces[",order[i],"]:",leafpieces[order[i]],"leafpieces[",order[i+1],"]:",leafpieces[order[i+1]]);
    }

    // component ConcatLeaf[4];
    // ConcatLeaf[0] = ConcatNumber();
    // ConcatLeaf[1] = ConcatNumber();
    // ConcatLeaf[2] = ConcatNumber();
    // ConcatLeaf[3] = ConcatNumber();
    component hashleaf[4];
    for(var i=0;i<4;i++){
        hashleaf[i]=Poseidon(6);
        hashleaf[i].inputs[0] <-- leafpieces[i*6];
        hashleaf[i].inputs[1] <-- leafpieces[i*6+1];
        hashleaf[i].inputs[2] <-- leafpieces[i*6+2];
        hashleaf[i].inputs[3] <-- leafpieces[i*6+3];
        hashleaf[i].inputs[4] <-- leafpieces[i*6+4];
        hashleaf[i].inputs[5] <-- leafpieces[i*6+5];
        leaf[i] <== hashleaf[i].out;
    }
     log("leaf[0]:",leaf[0],"leaf[1]:",leaf[1],"leaf[2]:",leaf[2],"leaf[3]:",leaf[3]);


    component SMTtree[4];
    SMTtree[0]=SMTProcessor(2);
    SMTtree[0].fnc <== [1,0];
    SMTtree[0].oldRoot <== 0;
    SMTtree[0].siblings <== [ 0, 0 ];
    SMTtree[0].oldKey <== 0;
    SMTtree[0].oldValue <== 0;
    SMTtree[0].isOld0 <== 1;
    SMTtree[0].newKey <== 0;
    SMTtree[0].newValue <== leaf[0];

    log("SMTtree[0].newRoot:",SMTtree[0].newRoot);

    SMTtree[1]=SMTProcessor(2);
    SMTtree[1].fnc <== [1,0];
    SMTtree[1].oldRoot <== SMTtree[0].newRoot;
    SMTtree[1].siblings <== [ 0, 0 ];
    SMTtree[1].oldKey <== 0;
    SMTtree[1].oldValue <== leaf[0];
    SMTtree[1].isOld0 <== 0;
    SMTtree[1].newKey <== 1;
    SMTtree[1].newValue <== leaf[1];

    log("SMTtree[1].newRoot:",SMTtree[1].newRoot);


    SMTtree[2]=SMTProcessor(2);
    SMTtree[2].fnc <== [1,0];
    SMTtree[2].oldRoot <== SMTtree[1].newRoot;
    component hash1=Poseidon(3);
    hash1.inputs[0] <== 1;
    hash1.inputs[1] <== leaf[1];
    hash1.inputs[2] <== 1;
    SMTtree[2].siblings[0] <== hash1.out;
    SMTtree[2].siblings[1] <== 0;
    SMTtree[2].oldKey <== 0;
    SMTtree[2].oldValue <== leaf[0];
    SMTtree[2].isOld0 <== 0;
    SMTtree[2].newKey <== 2;
    SMTtree[2].newValue <== leaf[2];

    log("SMTtree[2].newRoot:",SMTtree[2].newRoot);


    SMTtree[3]=SMTProcessor(2);
    SMTtree[3].fnc <== [1,0];
    SMTtree[3].oldRoot <== SMTtree[2].newRoot;
    component hash0=Poseidon(3);
    hash0.inputs[0] <== 0;
    hash0.inputs[1] <== leaf[0];
    hash0.inputs[2] <== 1;
    component hash2=Poseidon(3);
    hash2.inputs[0] <== 2;
    hash2.inputs[1] <== leaf[2];
    hash2.inputs[2] <== 1;
    component hash02=Poseidon(2);
    hash02.inputs[0] <== hash0.out;
    hash02.inputs[1] <== hash2.out;
    SMTtree[3].siblings[0] <== hash02.out;
    SMTtree[3].siblings[1] <== 0;
    SMTtree[3].oldKey <== 1;
    SMTtree[3].oldValue <== leaf[1];
    SMTtree[3].isOld0 <== 0;
    SMTtree[3].newKey <== 3;
    SMTtree[3].newValue <== leaf[3];

    log("SMTtree[3].newRoot:",SMTtree[3].newRoot);

    Root <== SMTtree[3].newRoot;

}

template changeDowner(DID_level,ID_level){
    //public signal
    signal input Old_Leaf_Downer;//?
    signal input New_Leaf_Downer;//?
    signal input DIDRoot;
    signal input HashedIDRoot;
    signal input DID_Key;//SMT的key


    //private signal
    
    signal input DIDu;
    signal input ID;
    signal input Salt;
    signal input enigma[8];
    signal input EnigmaRoot;
    signal input Old_PK_Downer[2];//?
    signal input New_PK_Downer[2];//?
    signal input SK_Owner;
    signal input order[24];
    signal input SIG_Owner[3];//这里在论文中应该是secp256k1签名，但验证开销太大，我的电脑跑不动。所以这里为了实现论文中的意思，不得已改回了poseidon签名。
    signal input SIG_New_Downer[3];
    signal input DID_MKT_Proof[DID_level];
    signal input HashedID_MKT_Proof[ID_level];
    signal input HashedID_Key;//SMT的key




   

    //构建DID树的叶子
    component DID_leaf_hash = Poseidon(5);
    DID_leaf_hash.inputs[0] <== DIDu;
    DID_leaf_hash.inputs[1] <== ID;
    DID_leaf_hash.inputs[2] <== Salt;
    DID_leaf_hash.inputs[3] <== Old_PK_Downer[0];
    DID_leaf_hash.inputs[4] <== Old_PK_Downer[1];
    DID_leaf_hash.out === Old_Leaf_Downer;

    //构建HashedID
    component hash=Poseidon(1);
    hash.inputs[0] <== ID;//F.e(ID)
    component hashSalt=Poseidon(2);
    hashSalt.inputs[0] <== hash.out;
    hashSalt.inputs[1] <== Salt;

    //从Owner的私钥生成Owner的公钥
    component PK_Owner = PrivToPubKey();
    PK_Owner.privKey <== SK_Owner;
    log("PK_Owner.pubKey[0]",PK_Owner.pubKey[0]);
    log("PK_Owner.pubKey[1]",PK_Owner.pubKey[1]);

    

    //构建HashedID树的叶子
    component HashedID_leaf_hash = Poseidon(4);
    HashedID_leaf_hash.inputs[0] <== hashSalt.out;
    HashedID_leaf_hash.inputs[1] <== PK_Owner.pubKey[0];
    HashedID_leaf_hash.inputs[2] <== PK_Owner.pubKey[1];
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
    DIDtree_verify.key <== DID_Key;
    DIDtree_verify.value <== Old_Leaf_Downer;

    //验证所构建HashedID树的叶子是否存在于HashedID树中
    component HashedIDtree_verify = SMTVerifier(ID_level);//26
    HashedIDtree_verify.enabled <== 1;
    HashedIDtree_verify.fnc <== 0;
    HashedIDtree_verify.root <== HashedIDRoot;
    HashedIDtree_verify.siblings <== HashedID_MKT_Proof;
    HashedIDtree_verify.oldKey <== 0;
    HashedIDtree_verify.oldValue <== 0;
    HashedIDtree_verify.isOld0 <== 0;
    HashedIDtree_verify.key <== HashedID_Key;
    HashedIDtree_verify.value <== HashedID_leaf_hash.out;


    //验证owner的签名是否有效

    //验证Owner对new Downer的签名
    component SIG_Verifier[2];
    SIG_Verifier[0]=EdDSAPoseidonVerifier();
    SIG_Verifier[0].enabled <== 1;
    SIG_Verifier[0].Ax <== PK_Owner.pubKey[0];
    SIG_Verifier[0].Ay <== PK_Owner.pubKey[1];
    SIG_Verifier[0].R8x <== SIG_Owner[0];
    SIG_Verifier[0].R8y <== SIG_Owner[1];
    SIG_Verifier[0].S <== SIG_Owner[2];
    SIG_Verifier[0].M <== Old_PK_Downer[0] + Old_PK_Downer[1] + New_PK_Downer[0] + New_PK_Downer[1];

    //验证用户确实持有新的Downer私钥
    SIG_Verifier[1]=EdDSAPoseidonVerifier();
    SIG_Verifier[1].enabled <== 1;
    SIG_Verifier[1].Ax <== New_PK_Downer[0];
    SIG_Verifier[1].Ay <== New_PK_Downer[1];
    SIG_Verifier[1].R8x <== SIG_New_Downer[0];
    SIG_Verifier[1].R8y <== SIG_New_Downer[1];
    SIG_Verifier[1].S <== SIG_New_Downer[2];
    SIG_Verifier[1].M <== Old_PK_Downer[0] + Old_PK_Downer[1] + hashSalt.out;

    //验证私钥来自Owner
   

    //该用户持有enigma，并且能够构成Root
    component RootContrust = RootContrust();
    RootContrust.SIG0[0] <== enigma[0];
    RootContrust.SIG0[1] <== enigma[1];
    RootContrust.SIG0[2] <== enigma[2];
    RootContrust.SIG1[0] <== enigma[3];
    RootContrust.SIG1[1] <== enigma[4];
    RootContrust.SIG1[2] <== enigma[5];
    RootContrust.ID <== ID;
    RootContrust.Salt <== Salt;
    RootContrust.PrivKey0 <== enigma[6];
    RootContrust.PrivKey1 <== enigma[7];
    RootContrust.order <== order;
    EnigmaRoot === RootContrust.Root;

    component NewLeaf = Poseidon(5);
    NewLeaf.inputs[0] <== DIDu;
    NewLeaf.inputs[1] <== ID;
    NewLeaf.inputs[2] <== Salt;
    NewLeaf.inputs[3] <== New_PK_Downer[0];
    NewLeaf.inputs[4] <== New_PK_Downer[1];
    New_Leaf_Downer === NewLeaf.out;
    
}

component main{public [ Old_Leaf_Downer,New_Leaf_Downer,DIDRoot,HashedIDRoot,DID_Key] } = changeDowner(3,3);
