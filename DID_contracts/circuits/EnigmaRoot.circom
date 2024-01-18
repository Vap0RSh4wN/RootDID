pragma circom  2.0.6;
include "../../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/smt/smtprocessor.circom";

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

template EnigmaRoot(){
    //public signal
    signal input OldRoot;
    signal input HashedID;
    signal input NewOwner;
    signal input NewRoot;
    // signal input SIGfromControlor;
    //private signal
    signal input SIG0[3];
    signal input SIG1[3];
    signal input ID;
    signal input Salt;
    signal input PrivKey0;
    signal input PrivKey1;

    signal input order[24];//2,11,0,3,10,1... 每个的位置。比如Split[0]的前一半在2，后一半在11
    // signal input order[24][2];
    // signal input order[12][4];
    //如order[0]=0233，意味着字段index为0（比如SIG0[0]，分为两份，前一半,后一半）,分别在leaf序号为0的第2份和为3的第3份。 
    //intermidiate signal
    signal PubKey[4];
    
    //check hash(ID) == HashedID
    log("ID:",ID);
    component hash=Poseidon(1);
    hash.inputs[0] <== ID;//F.e(ID)
    component hashSalt=Poseidon(2);
    hashSalt.inputs[0] <== hash.out;
    hashSalt.inputs[1] <== Salt;


    log("hash.out:",hash.out,"Salt",Salt,"hashSalt.out:",hashSalt.out);

    hashSalt.out === HashedID;

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
        // ConcatLeaf[i].in[0] <-- leafpieces[i*6];
        // ConcatLeaf[i].in[1] <-- leafpieces[i*6+1];
        // ConcatLeaf[i].in[2] <-- leafpieces[i*6+2];
        // ConcatLeaf[i].in[3] <-- leafpieces[i*6+3];
        // ConcatLeaf[i].in[4] <-- leafpieces[i*6+4];
        // ConcatLeaf[i].in[5] <-- leafpieces[i*6+5];
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

    SMTtree[3].newRoot === OldRoot;

    signal NewOwnerSquare;
    signal NewRootSquare;
    // signal NewSigSquare;
    NewOwnerSquare <== NewOwner * NewOwner;
    NewRootSquare <== NewRoot * NewRoot;
    // NewSigSquare <== SIGfromControlor * SIGfromControlor;

}   

component main{public [ OldRoot,HashedID,NewOwner,NewRoot ] } = EnigmaRoot();

/*
在代码中，enabled被用作信号输入，用于控制一些组件的启用或禁用。通过设置enabled的值，可以选择性地启用或禁用与该信号相关联的组件。
在EdDSAPoseidonVerifier模板中，enabled被用于控制以下组件的启用或禁用：
compConstant.out*enabled === 0;：当enabled为1时，compConstant组件的输出为0，否则输出为非零值。
isZero.out*enabled === 0;：当enabled为1时，isZero组件的输出为0，否则输出为非零值。
eqCheckX.enabled <== enabled;和eqCheckY.enabled <== enabled;：根据enabled的值，决定是否启用eqCheckX和eqCheckY组件。
通过控制enabled的值，可以选择性地启用或禁用这些组件，从而控制模板的行为和计算结果。具体来说，当enabled为1时，相关组件将被启用，计算结果将包括这些组件的输出；当enabled为0时，相关组件将被禁用，计算结果将不包括这些组件的输出。

*/