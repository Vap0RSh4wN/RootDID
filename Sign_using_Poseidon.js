const chai =require("chai") ;
const  { Scalar } =require("ffjavascript");

const assert = chai.assert;
const buildEddsa =require("circomlibjs").buildEddsa;

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

(async () => {
    let eddsa = await buildEddsa();

const F = eddsa.babyJub.F;
const msgBuf = fromHexString("000102030405060708090000");

const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(msgBuf, 0));

//  const prvKey = crypto.randomBytes(32);

const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");

const pubKey = eddsa.prv2pub(prvKey);

assert(F.eq(pubKey[0], F.e("13277427435165878497778222415993513565335242147425444199013288855685581939618")));
assert(F.eq(pubKey[1], F.e("13622229784656158136036771217484571176836296686641868549125388198837476602820")));

const pPubKey = eddsa.babyJub.packPoint(pubKey);

const signature = eddsa.signPoseidon(prvKey, msg);

console.log(signature);
// console.log(F.toString(signature.R8[0]));
assert(F.eq(signature.R8[0], F.e("11384336176656855268977457483345535180380036354188103142384839473266348197733")));
// console.log(F.toString(signature.R8[1]));
assert(F.eq(signature.R8[1], F.e("15383486972088797283337779941324724402501462225528836549661220478783371668959")));
// console.log(Scalar.toString(signature.S));
assert(Scalar.eq(signature.S, Scalar.e("1672775540645840396591609181675628451599263765380031905495115170613215233181")));

const pSignature = eddsa.packSignature(signature);
console.log("p\n"+pSignature);


// console.log(toHexString(pSignature));
assert.equal(toHexString(pSignature), ""+
    "dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2"+
    "9d043ece562a8f82bfc0adb640c0107a7d3a27c1c7c1a6179a0da73de5c1b203");

const uSignature = eddsa.unpackSignature(pSignature);
console.log("u\n"+uSignature);

assert(eddsa.verifyPoseidon(msg, uSignature, pubKey));
})();