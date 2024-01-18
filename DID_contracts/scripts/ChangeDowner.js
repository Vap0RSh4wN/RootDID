const buildEddsa =require("circomlibjs").buildEddsa;
const newMemEmptyTrie = require("circomlibjs").newMemEmptyTrie;
const buildPoseidon = require("circomlibjs").buildPoseidon;
const fs = require('fs')
const path = require('path');
var createBlakeHash = require('blake-hash');
const { Scalar } =require("ffjavascript");
const chai = require("chai");
const assert = chai.assert;


function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var createBlakeHash__default = /*#__PURE__*/_interopDefaultLegacy(createBlakeHash);


const IDu = 220421209901010375n;

//old_Downer_privkey
var old_Downer_privkey = 16516287312154619925946469371660119799016052886604538636235305334289142825809n;
var DIDu = 123456789987654321123456789987654321n;

//Owmer
var Owner_privkey = 13584982670588872009031068202617858392048568605656810564571936381294184456430n;

//new_Downer_privkey
var new_Downer_privkey = 4776106638794603048617556176080830669555379762597227674508103893601488166059n;

function Base24ToDecimalArray(str) {
    const radix = 24;
    const arr = str.split('');
    const decimalArray = arr.map((char) => parseInt(char, radix));
    return decimalArray;
}

async function formatPrivKeyForBabyJub(prv){
    const pruneBuffer=(buff) =>{
        buff[0] = buff[0] & 0xF8;
        buff[31] = buff[31] & 0x7F;
        buff[31] = buff[31] | 0x40;
        return buff;
    }
    const sBuff = pruneBuffer(createBlakeHash__default["default"]("blake512").update(Buffer.from(prv,"hex")).digest());
    let s = Scalar.fromRprLE(sBuff, 0, 32);
    return Scalar.shr(s,3);
}

async function BinaryConstruct(prvKey0_BigInt,prvKey1_BigInt){
    const prvKey0 = Buffer.from(prvKey0_BigInt.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[0]));
    console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[1]));
    const prvKey1 = Buffer.from(prvKey1_BigInt.toString(16),"hex");
    console.log('eddsa.prv2pub(prvKey1): '+F.toString(eddsa.prv2pub(prvKey1)[0]))
    console.log('eddsa.prv2pub(prvKey1): '+F.toString(eddsa.prv2pub(prvKey1)[1]))
    const signature0 = eddsa.signPoseidon(prvKey0, F.e(IDu));//F.e(1234)
    const signature1 = eddsa.signPoseidon(prvKey1, F.e(IDu));
    console.log("signature0.R8[0]",F.toObject(signature0.R8[0]));
    console.log("signature0.R8[1]",F.toObject(signature0.R8[1]));
    console.log("signature0.S",signature0.S);
    console.log("signature1.R8[0]",F.toObject(signature1.R8[0]));
    console.log("signature1.R8[1]",F.toObject(signature1.R8[1]));
    console.log("signature1.S",signature1.S);

    var spilt = new Array(12);
    spilt[0] = F.toObject(signature0.R8[0]);
    spilt[1] = F.toObject(signature0.R8[1]);
    spilt[2] = signature0.S;
    spilt[3] = F.toObject(signature1.R8[0]);
    spilt[4] = F.toObject(signature1.R8[1]);
    spilt[5] = signature1.S;
    spilt[6] = F.toString(eddsa.prv2pub(prvKey0)[0]);
    spilt[7] = F.toString(eddsa.prv2pub(prvKey0)[1]);
    spilt[8] = F.toString(eddsa.prv2pub(prvKey1)[0]);
    spilt[9] = F.toString(eddsa.prv2pub(prvKey1)[1]);
    //应该是formatPrivKeyForBabyJub后的私钥
    spilt[10] = await formatPrivKeyForBabyJub(prvKey0_BigInt.toString(16));
    spilt[11] = await formatPrivKeyForBabyJub(prvKey1_BigInt.toString(16));
    console.log("spilt[10]: "+spilt[10]);
    console.log("spilt[11]: "+spilt[11]);


    var binary=new Array(12);
    binary[0] = spilt[0].toString(2).padStart(256, '0');
    binary[1] = spilt[1].toString(2).padStart(256, '0');
    binary[2] = spilt[2].toString(2).padStart(256, '0');//S也是256位，补上的一位0转成十六进制就消失了
    binary[3] = spilt[3].toString(2).padStart(256, '0');
    binary[4] = spilt[4].toString(2).padStart(256, '0');
    binary[5] = spilt[5].toString(2).padStart(256, '0');//S也是256位，补上的一位0转成十六进制就消失了
    binary[6] = BigInt(spilt[6]).toString(2).padStart(256, '0');
    binary[7] = BigInt(spilt[7]).toString(2).padStart(256, '0');
    binary[8] = BigInt(spilt[8]).toString(2).padStart(256, '0');
    binary[9] = BigInt(spilt[9]).toString(2).padStart(256, '0');
    binary[10] = spilt[10].toString(2).padStart(256, '0');
    binary[11] = spilt[11].toString(2).padStart(256, '0');
    return [spilt,binary];
}

async function LeafsConstruct(binary,order){
    var leafpieces = new Array(24);
    var j=0;
        for(let i=0;i<24;i=i+2){
            leafpieces[order[i]] = BigInt('0b' + binary[j].substring(0, 128));
            leafpieces[order[i+1]] = BigInt('0b' + binary[j].substring(128, 256));
            j++;
            console.log("leafpieces[",order[i],"]:",leafpieces[order[i]],"leafpieces[",order[i+1],"]:",leafpieces[order[i+1]])
        }
    var leaf = new Array(4);
    let l0,l1,l2,l3,l4,l5;
    for(let i = 0;i < 4;i++){
        l0 = leafpieces[i*6];
        l1 = leafpieces[i*6+1];
        l2 = leafpieces[i*6+2];
        l3 = leafpieces[i*6+3];
        l4 = leafpieces[i*6+4];
        l5 = leafpieces[i*6+5];
        leaf[i] = poseidon([l0,l1,l2,l3,l4,l5]);
        // console.log("leaf["+i+"] is: "+F.toObject(leaf[i]));
    }
    return leaf;
}

async function treeInsert(tree, _key, _value) {
    const key = F.e(_key);
    const value = F.e(_value)
    const res = await tree.insert(key,value);
    let siblings = res.siblings;
    // console.log(siblings.length)
    for (let i=0; i<siblings.length; i++) siblings[i] = F.toObject(siblings[i]);
    while (siblings.length<2) siblings.push(0);
    // const w = {
    //     fnc: [1,0],
    //     oldRoot: F.toObject(res.oldRoot),
    //     siblings: siblings,
    //     oldKey: res.isOld0 ? 0 : F.toObject(res.oldKey),
    //     oldValue: res.isOld0 ? 0 : F.toObject(res.oldValue),
    //     isOld0: res.isOld0 ? 1 : 0,
    //     newKey: F.toObject(key),
    //     newValue: F.toObject(value)
    // };
    // console.log(w);
}

async function RootConstruct(leaf){
    tree = await newMemEmptyTrie();
    const key0 = F.e(0);
    const value0 = F.e(leaf[0]);
    await treeInsert(tree, key0, value0);
    const key1 = F.e(1);
    const value1 = F.e(leaf[1]);
    await treeInsert(tree, key1, value1);
    const key2 = F.e(2);
    const value2 = F.e(leaf[2]);
    await treeInsert(tree, key2, value2);
    const key3 = F.e(3);
    const value3= F.e(leaf[3]);
    await treeInsert(tree, key3, value3);
    return tree.root;
}

async function loadEnigma(){
    var prvKey0,prvKey1,salt,order;
    const filePath = path.join(__dirname, '../enigma/Dontloseit_New.txt');
    let arr = fs.readFileSync(filePath, 'utf-8').split('-');
    prvKey0 = arr[1];
    prvKey1 = arr[2];
    salt = arr[3];
    order = arr[4];
    let [inputs,binary] = await BinaryConstruct(BigInt('0x'+prvKey0),BigInt('0x'+prvKey1));
    console.log("inputs"+inputs)
    order = Base24ToDecimalArray(order);
    var leaf = await LeafsConstruct(binary,order);
    var root = await RootConstruct(leaf);
    return [salt,inputs,root,order];
    // console.log(F.toObject(root));
   
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

async function testExclusion(string,tree, _key) {
    const key = tree.F.e(_key);
    const res = await tree.find(key);

    
    let siblings = res.siblings;
    for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
    while (siblings.length<10) siblings.push(0);

    const w = {
        enabled: 1,
        fnc: 1,
        root: tree.F.toObject(tree.root),
        siblings: siblings,
        oldKey: res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey),
        oldValue: res.isOld0 ? 0 : tree.F.toObject(res.notFoundValue),
        isOld0: res.isOld0 ? 1 : 0,
        key: tree.F.toObject(key),
        value: 0
    };

    console.log("4w",w);

}

async function main(){
    eddsa = await buildEddsa();
    F = eddsa.babyJub.F;
    poseidon = await buildPoseidon();

    var [salt,inputs,oldRoot,order] = await loadEnigma();//获得构建零知识证明的input

    console.log("oldRoot: "+F.toString(oldRoot));
    console.log("salt: "+BigInt("0x"+salt));
    salt = BigInt("0x"+salt);
    console.log("inputs: "+inputs);
    console.log("order: "+order);

    var HashedID = poseidon([poseidon([IDu]),salt.toString()]);

    //old_Downer_privkey
    const prvKey0 = Buffer.from(old_Downer_privkey.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('old_Downer_privkey eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[0]));
    console.log('old_Downer_privkey eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[1]));
  
    //new_Downer_privkey
    const prvKey2 = Buffer.from(new_Downer_privkey.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('new_Downer_privkey eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey2)[0]));
    console.log('new_Downer_privkey eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey2)[1]));
    const signature2 = eddsa.signPoseidon(prvKey2, F.e(BigInt(F.toString(eddsa.prv2pub(prvKey0)[0]))+BigInt(F.toString(eddsa.prv2pub(prvKey0)[1]))+BigInt(F.toObject(HashedID))));//F.e(1234)
    console.log("new_Downer_privkey signature0.R8[0]",F.toObject(signature2.R8[0]));
    console.log("new_Downer_privkey signature0.R8[1]",F.toObject(signature2.R8[1]));
    console.log("new_Downer_privkey signature0.S",signature2.S);


    //SIG Owner_privkey
    const prvKey1 = Buffer.from(Owner_privkey.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('SIG_Owner eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey1)[0]));
    console.log('SIG_Owner eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey1)[1]));
    const signature1 = eddsa.signPoseidon(prvKey1, F.e(BigInt(F.toString(eddsa.prv2pub(prvKey0)[0]))+BigInt(F.toString(eddsa.prv2pub(prvKey0)[1]))+BigInt(F.toString(eddsa.prv2pub(prvKey2)[0]))+BigInt(F.toString(eddsa.prv2pub(prvKey2)[1]))));//F.e(1234)
    console.log("SIG_Owner signature0.R8[0]",F.toObject(signature1.R8[0]));
    console.log("SIG_Owner signature0.R8[1]",F.toObject(signature1.R8[1]));
    console.log("SIG_Owner signature0.S",signature1.S);

    var DIDleaf = poseidon([DIDu,IDu,salt,F.toString(eddsa.prv2pub(prvKey0)[0]),F.toString(eddsa.prv2pub(prvKey0)[1])]);
    var HashedIDleaf = poseidon([HashedID,F.toString(eddsa.prv2pub(prvKey1)[0]),F.toString(eddsa.prv2pub(prvKey1)[1]),oldRoot]);
    console.log("DIDleaf",F.toObject(DIDleaf));
    console.log("HashedID",F.toObject(HashedID));
    console.log("HashedIDleaf",F.toObject(HashedIDleaf));

    var NewDIDleaf = poseidon([DIDu,IDu,salt,F.toString(eddsa.prv2pub(prvKey2)[0]),F.toString(eddsa.prv2pub(prvKey2)[1])]);
    console.log("NewDIDleaf",F.toObject(NewDIDleaf));

    var SK_Owner_format = await formatPrivKeyForBabyJub(Owner_privkey.toString(16));
    console.log("SK_Owner_format",SK_Owner_format);

    //oldRoot is EnigmaRoot

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
    await testExclusion("id",treed, 4);
    await testExclusion("id",treed, 5);

}
main();