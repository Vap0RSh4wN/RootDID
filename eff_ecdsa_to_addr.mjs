import {  sign, Point } from '@noble/secp256k1';
import {buildPoseidon} from "circomlibjs";
import {buildEddsa} from "circomlibjs";
import {newMemEmptyTrie} from "circomlibjs";
import {assert} from "chai";


function bigint_to_array(n, k, x) {
    let mod = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret = [];
    var x_temp = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}
function BigIntToArray(n, k, x) {
    let mod = 1n << BigInt(n);
    let ret = [];
    var x_temp = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp >> BigInt(n);
    }
    return ret;
}

function bigint_to_tuple(x) {
    let mod = 2n ** 64n;
    let ret= [0n, 0n, 0n, 0n];

    var x_temp = x;
    for (var idx = 0; idx < ret.length; idx++) {
        ret[idx] = x_temp % mod;
        x_temp = x_temp / mod;
    }
    return ret;
}

// bigendian
function bigint_to_Uint8Array(x) {
    var ret = new Uint8Array(32);
    for (var idx = 31; idx >= 0; idx--) {
        ret[idx] = Number(x % 256n);
        x = x / 256n;
    }
    return ret;
}
// bigendian
function Uint8Array_to_bigint(x) {
    var ret = 0n;
    for (var idx = 0; idx < x.length; idx++) {
        ret = ret * 256n;
        ret = ret + BigInt(x[idx]);
    }
    return ret;
}

async function treeInsert(tree, _key, _value) {
    const key = F.e(_key);
    const value = F.e(_value)
    const res = await tree.insert(key,value);
    let siblings = res.siblings;
    // console.log(siblings.length)
    for (let i=0; i<siblings.length; i++) siblings[i] = F.toObject(siblings[i]);
    while (siblings.length<3) siblings.push(0);

    const w = {
        fnc: [1,0],
        oldRoot: F.toObject(res.oldRoot),
        siblings: siblings,
        oldKey: res.isOld0 ? 0 : F.toObject(res.oldKey),
        oldValue: res.isOld0 ? 0 : F.toObject(res.oldValue),
        isOld0: res.isOld0 ? 1 : 0,
        newKey: F.toObject(key),
        newValue: F.toObject(value)
    };
    console.log("w",w);
}

async function testInclusion(string,tree, _key) {
    const key = tree.F.e(_key);
    const res = await tree.find(key);

    assert(res.found);
    let siblings = res.siblings;
    for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
    while (siblings.length<3) siblings.push(0);
    console.log(string+" siblings",siblings);

}


async function SIG(string,privkey,msghash_bigint){
    var pubkey = Point.fromPrivateKey(privkey);
    var pub0 = pubkey.x;
    var pub1 = pubkey.y
    var msghash_array = bigint_to_array(64, 4, msghash_bigint);
    var msghash_array_ = BigIntToArray(64, 4, msghash_bigint);
    console.log("msghash_array", msghash_array);
    console.log("msghash_array_", msghash_array_);
    var msghash = bigint_to_Uint8Array(msghash_bigint);
    // in compact format: r (big-endian), 32-bytes + s (big-endian), 32-bytes
    var sig = await sign(msghash, bigint_to_Uint8Array(privkey), {canonical: true, der: false})
    var r = sig.slice(0, 32);
    var r_bigint = Uint8Array_to_bigint(r);
    var s = sig.slice(32, 64);
    var s_bigint = Uint8Array_to_bigint(s);
    
    console.log(string.slice(4,)+" privkey", bigint_to_tuple(privkey))
    var r_array = bigint_to_array(64, 4, r_bigint);
    var s_array = bigint_to_array(64, 4, s_bigint);
    var msghash_array = bigint_to_array(64, 4, msghash_bigint);
    var pub0_array = bigint_to_array(64, 4, pub0);
    var pub1_array = bigint_to_array(64, 4, pub1);
    var res = 1n;
    
    console.log('r', r_bigint);
    console.log('s', s_bigint);
    var args={"r": r_array,"s": s_array,"msghash": msghash_array,"pubkey": [pub0_array, pub1_array]};
    console.log(string,args);
};
let eddsa;
    let poseidon;
    let F;
(async ()=>{
    var DIDv = 456789987654321123456789987654321123n;
    const IDu = 220421209901010375n;
    const salt = 19575205003271201733456932019346756354564123523504998527218008003572080943789n;
    const EnigmaRoot =624229129179502190129466872784257182080047783356457872202759975210899853509n;

    //Downer
    var Downer_privkey = 40606737760334725431406512677033654118342507952694270066784247067953537247501n;
    console.log(BigInt('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d','hex'));
    //BigInt('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d','hex')
    var Downer_address = 642829559307850963015472508762062935916233390536n;
    //0x70997970C51812dc3A010C7d01b50e0d17dc79C8
    var DIDu = 123456789987654321123456789987654321n;
    var attribute_withoutDID = 987654321123456789987654321123456789n;
    var SIG_Downer = await SIG("SIG_Downer",Downer_privkey,attribute_withoutDID+DIDu+DIDv);
    //Owmer
    var Owner_privkey = 77814517325470205911140941194401928579557062014761831930645393041380819009408n;
    //0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    var Owner_address = 1390849295786071768276380950238675083608645509734n;
    //0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

    var SIG_Owner = await SIG("SIG_Owner",Owner_privkey,DIDu);
    //issuer
    var issuer_privkey = 88549154299169935420064281163296845505587953610183896504176354567359434168161n
    console.log("DIDu+attribute_withoutDID",DIDu+attribute_withoutDID);
    var SIG_issuer = await SIG("SIG_issuer",issuer_privkey,attribute_withoutDID+DIDu);

    
    eddsa = await buildEddsa();
    F = eddsa.babyJub.F;
    poseidon = await buildPoseidon();

    var p = 9621768605262634734918713082183293757924219030966503451274639623013218319386n;
    const prvKey0 = Buffer.from(p.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[0]));
    console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[1]));
    const signature0 = eddsa.signPoseidon(prvKey0, F.e(DIDu+attribute_withoutDID));//F.e(1234)
    console.log("signature0.R8[0]",F.toObject(signature0.R8[0]));
    console.log("signature0.R8[1]",F.toObject(signature0.R8[1]));
    console.log("signature0.S",signature0.S);

    var DIDleaf = poseidon([DIDu,IDu,salt,Downer_address]);
    var HashedID = poseidon([poseidon([IDu]),salt.toString()]);
    var HashedIDleaf = poseidon([HashedID,Owner_address,EnigmaRoot]);
    console.log("DIDleaf",F.toObject(DIDleaf));
    console.log("HashedID",F.toObject(HashedID));
    console.log("HashedIDleaf",F.toObject(HashedIDleaf));

    var leafwhatever = poseidon([DIDu]);
    var leafwhatever2 = poseidon([IDu]);


    //did tree
    var tree = await newMemEmptyTrie();
    const key0 = F.e(0);
    const value0 = F.e(leafwhatever);
    await treeInsert(tree, key0, value0);
    const key1 = F.e(1);
    const value1 = F.e(leafwhatever);
    await treeInsert(tree, key1, value1);
    const key2 = F.e(2);
    const value2 = F.e(leafwhatever2);
    await treeInsert(tree, key2, value2);
    const key3 = F.e(3);
    const value3= F.e(DIDleaf);
    await treeInsert(tree, key3, value3);
    console.log("did tree",F.toObject(tree.root)) ;

    //id tree
    var treed = await newMemEmptyTrie();
    const key0d = F.e(0);
    const value0d = F.e(leafwhatever2);
    await treeInsert(treed, key0d, value0d);
    const key1d = F.e(1);
    const value1d = F.e(leafwhatever2);
    await treeInsert(treed, key1d, value1d);
    const key2d = F.e(2);
    const value2d = F.e(leafwhatever);
    await treeInsert(treed, key2d, value2d);
    const key3d = F.e(3);
    const value3d= F.e(HashedIDleaf);
    await treeInsert(treed, key3d, value3d);
    console.log("id tree",F.toObject(treed.root)) ;

    await testInclusion("did",tree, 3);
    await testInclusion("id",treed, 3);
})();
