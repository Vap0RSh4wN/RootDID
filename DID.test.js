const chai = require("chai");
const buildEddsa =require("circomlibjs").buildEddsa;
const { Scalar } =require("ffjavascript");
const assert = chai.assert;
const newMemEmptyTrie = require("circomlibjs").newMemEmptyTrie;
const buildPoseidon = require("circomlibjs").buildPoseidon;
const getHashes = require("circomlibjs").buildSMT;

let babyJub;
let eddsa;
let poseidon;
let tree;
let Fr;
(async () => {
    eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;
    poseidon = await buildPoseidon();
    
const prvKey0 = Buffer.from("fc813aed5ed79547f5b4e0f7708033860a5291e43cf1b7a11592ec911ba141c","hex");
// console.log('eddsa.prv2pub(prvKey0)'+eddsa.prv2pub(prvKey0))
console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[0]));
console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[1]));
const prvKey1 = Buffer.from("2b542b85723c427b3ab199e291e0404146e9d4dcfbb5d07c7a833773e03bcc8b","hex");
// console.log('eddsa.prv2pub(prvKey1)'+eddsa.prv2pub(prvKey1))
console.log('eddsa.prv2pub(prvKey1): '+F.toString(eddsa.prv2pub(prvKey1)[0]))
console.log('eddsa.prv2pub(prvKey1): '+F.toString(eddsa.prv2pub(prvKey1)[1]))

const ID=220421209901010375;//这里如果外面带引号变成ID字符串和不带引号的ID数字哈希值是不一样的
const salt=19575205003271201733456932019346756354564123523504998527218008003572080943789;
const res2 = poseidon([poseidon([ID]),salt]);//最后别忘了加盐，再思考一下这里的盐是什么
console.log("poseidon([ID]): "+F.toObject(res2));

const signature0 = eddsa.signPoseidon(prvKey0, F.e(ID));//F.e(1234)
const signature1 = eddsa.signPoseidon(prvKey1, F.e(ID));
console.log("signature0.R8[0]",F.toObject(signature0.R8[0]));
console.log("signature0.R8[1]",F.toObject(signature0.R8[1]));
console.log("signature0.S",signature0.S);
console.log("signature1.R8[0]",F.toObject(signature1.R8[0]));
console.log("signature1.R8[1]",F.toObject(signature1.R8[1]));
console.log("signature1.S",signature1.S);

var spilt0 = F.toObject(signature0.R8[0]);
var spilt1 = F.toObject(signature0.R8[1]);
var spilt2 = signature0.S;
var spilt3 = F.toObject(signature1.R8[0]);
var spilt4 = F.toObject(signature1.R8[1]);
var spilt5 = signature1.S;
var spilt6 = F.toString(eddsa.prv2pub(prvKey0)[0]);
var spilt7 = F.toString(eddsa.prv2pub(prvKey0)[1]);
var spilt8 = F.toString(eddsa.prv2pub(prvKey1)[0]);
var spilt9 = F.toString(eddsa.prv2pub(prvKey1)[1]);
//应该是formatPrivKeyForBabyJub后的私钥
var spilt10 = BigInt("5104791857392701538134495173544631264538363554503733740411421273698560122573");
var spilt11 = BigInt("6697841158982774174450224172792441617183630555897667047167253061656097367153");
var binary=new Array(12);
binary[0] = spilt0.toString(2).padStart(256, '0');
binary[1] = spilt1.toString(2).padStart(256, '0');
binary[2] = spilt2.toString(2).padStart(256, '0');//S也是256位，补上的一位0转成十六进制就消失了
binary[3] = spilt3.toString(2).padStart(256, '0');
binary[4] = spilt4.toString(2).padStart(256, '0');
binary[5] = spilt5.toString(2).padStart(256, '0');//S也是256位，补上的一位0转成十六进制就消失了
binary[6] = BigInt(spilt6).toString(2).padStart(256, '0');
binary[7] = BigInt(spilt7).toString(2).padStart(256, '0');
binary[8] = BigInt(spilt8).toString(2).padStart(256, '0');
binary[9] = BigInt(spilt9).toString(2).padStart(256, '0');
binary[10] = spilt10.toString(2).padStart(256, '0');
binary[11] = spilt11.toString(2).padStart(256, '0');
// console.log(binary2);
// console.log(binary2.substring(0, 128));
// console.log(BigInt('0b' + binary2.substring(0, 128)).toString(16))
// console.log(binary2.substring(128, 256));
// console.log(BigInt('0b' + binary2.substring(128, 256)).toString(16))

var arr = new Array(24);
for(var i=0;i<24;i++){
    arr[i]=i;
}
var order=[5,23,8,21,7,19,22,0,18,9,11,4,14,1,6,12,20,2,3,17,10,13,16,15];
// var order=arr.sort(() => Math.random() - 0.5);
// console.log(order);
var leafpieces = new Array(24);
var j=0;
    for(var i=0;i<24;i=i+2){
        leafpieces[order[i]] = BigInt('0b' + binary[j].substring(0, 128));
        leafpieces[order[i+1]] = BigInt('0b' + binary[j].substring(128, 256));
        j++;
        console.log("leafpieces[",order[i],"]:",leafpieces[order[i]],"leafpieces[",order[i+1],"]:",leafpieces[order[i+1]])
    }
var leaf= new Array(4);
let l0,l1,l2,l3,l4,l5;
for(var i=0;i<4;i++){
    l0 = leafpieces[i*6];
    l1 = leafpieces[i*6+1];
    l2 = leafpieces[i*6+2];
    l3 = leafpieces[i*6+3];
    l4 = leafpieces[i*6+4];
    l5 = leafpieces[i*6+5];
    leaf[i] = poseidon([l0,l1,l2,l3,l4,l5]);
    console.log("leaf["+i+"] is: "+F.toObject(leaf[i]));
}

tree = await newMemEmptyTrie();
Fr = tree.F;
async function testInsert(tree, _key, _value) {
    const key = tree.F.e(_key);
    const value = tree.F.e(_value)
    const res = await tree.insert(key,value);
    let siblings = res.siblings;
    console.log(siblings.length)
    for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
    while (siblings.length<2) siblings.push(0);
    const w = {
        fnc: [1,0],
        oldRoot: tree.F.toObject(res.oldRoot),
        siblings: siblings,
        oldKey: res.isOld0 ? 0 : tree.F.toObject(res.oldKey),
        oldValue: res.isOld0 ? 0 : tree.F.toObject(res.oldValue),
        isOld0: res.isOld0 ? 1 : 0,
        newKey: tree.F.toObject(key),
        newValue: tree.F.toObject(value)
    };
    console.log(w);
    console.log(tree.F.toObject(res.newRoot));
}
const key0 = Fr.e(0);
const value0 = Fr.e(leaf[0]);
await testInsert(tree, key0, value0);
const key1 = Fr.e(1);
const value1 = Fr.e(leaf[1]);
await testInsert(tree, key1, value1);
const key2 = Fr.e(2);
const value2 = Fr.e(leaf[2]);
await testInsert(tree, key2, value2);
const key3 = Fr.e(3);
const value3= Fr.e(leaf[3]);
await testInsert(tree, key3, value3);


var inw = new Array(768);
for(var i=0;i<768;i++){
    inw[i]= Math.random(1)< 0.5 ? 0 : 1;
}
var lc1=0;

var e2 = 1;
for (var i = 0; i<768; i++) {
    lc1 += inw[i] * e2;
    e2 = e2 + e2;
}
console.log("lc1: "+BigInt(lc1));

// var integer = parseInt(hex, 16);
// var binary = integer.toString(2);
// console.log(binary); // "1010"


})();

