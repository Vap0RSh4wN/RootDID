import {  sign, Point } from '@noble/secp256k1';
import {buildPoseidon} from "circomlibjs";
import {buildEddsa} from "circomlibjs";
import {newMemEmptyTrie} from "circomlibjs";
import {assert} from "chai";

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

let eddsa;
let poseidon;
let F;
(async ()=>{
    var DIDv = 456789987654321123456789987654321123n;
    const IDu = 220421209901010375n;
    const salt = 19575205003271201733456932019346756354564123523504998527218008003572080943789n;
    const EnigmaRoot =624229129179502190129466872784257182080047783356457872202759975210899853509n;
    const id_claim = 123n;

    //Downer
    var Downer_privkey = 16516287312154619925946469371660119799016052886604538636235305334289142825809n;
    var DIDu = 123456789987654321123456789987654321n;
    var attribute_withoutDID = 987654321123456789987654321123456789n;
    //Owmer
    var Owner_privkey = 77814517325470205911140941194401928579557062014761831930645393041380819009408n;
    //0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    var Owner_address = 1390849295786071768276380950238675083608645509734n;
    //0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

    console.log(" Owner_privkey", bigint_to_tuple(Owner_privkey))

    //issuer
    var issuer_privkey = 4776106638794603048617556176080830669555379762597227674508103893601488166059n;
    console.log("DIDu+attribute_withoutDID",DIDu+attribute_withoutDID);

    
    eddsa = await buildEddsa();
    F = eddsa.babyJub.F;
    poseidon = await buildPoseidon();

    //Downer_privkey
    const prvKey0 = Buffer.from(Downer_privkey.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('SIG_Downer eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[0]));
    console.log('SIG_Downer eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[1]));
    const signature0 = eddsa.signPoseidon(prvKey0, F.e(id_claim+attribute_withoutDID+DIDu+DIDv));//F.e(1234)
    console.log("SIG_Downer signature0.R8[0]",F.toObject(signature0.R8[0]));
    console.log("SIG_Downer signature0.R8[1]",F.toObject(signature0.R8[1]));
    console.log("SIG_Downer signature0.S",signature0.S);


    //Owner_privkey
    const prvKey1 = Buffer.from(Owner_privkey.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('SIG_Owner eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey1)[0]));
    console.log('SIG_Owner eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey1)[1]));
    const signature1 = eddsa.signPoseidon(prvKey1, F.e(DIDu));//F.e(1234)
    console.log("SIG_Owner signature0.R8[0]",F.toObject(signature1.R8[0]));
    console.log("SIG_Owner signature0.R8[1]",F.toObject(signature1.R8[1]));
    console.log("SIG_Owner signature0.S",signature1.S);

    //issuer_privkey
    const prvKey2 = Buffer.from(issuer_privkey.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('SIG_Issuer eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey2)[0]));
    console.log('SIG_Issuer eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey2)[1]));
    const signature2 = eddsa.signPoseidon(prvKey2, F.e(id_claim+attribute_withoutDID+DIDu));//F.e(1234)
    console.log("SIG_Issuer signature0.R8[0]",F.toObject(signature2.R8[0]));
    console.log("SIG_Issuer signature0.R8[1]",F.toObject(signature2.R8[1]));
    console.log("SIG_Issuer signature0.S",signature2.S);


    var DIDleaf = poseidon([DIDu,IDu,salt,F.toString(eddsa.prv2pub(prvKey0)[0]),F.toString(eddsa.prv2pub(prvKey0)[1])]);
    var HashedID = poseidon([poseidon([IDu]),salt.toString()]);
    var HashedIDleaf = poseidon([HashedID,Owner_address,EnigmaRoot]);
    console.log("DIDleaf",F.toObject(DIDleaf));
    console.log("HashedID",F.toObject(HashedID));
    console.log("HashedIDleaf",F.toObject(HashedIDleaf));

    var sybli_value = poseidon([poseidon([IDu]),salt,attribute_withoutDID]);
    console.log("sybli_value",F.toObject(sybli_value));


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
