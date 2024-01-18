// const chai =require("chai") ;
const  { Scalar } =require("ffjavascript");
const buildPoseidon = require("circomlibjs").buildPoseidon;


// const assert = chai.assert;
const buildEddsa =require("circomlibjs").buildEddsa;

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

(async () => {
    let eddsa = await buildEddsa();
    let poseidon = await buildPoseidon();
    const F = eddsa.babyJub.F;
    let ID=220421209901010375n;
    console.log("poseidon([ID]): "+F.toObject(poseidon([ID])));
    console.log("ID.toString(): "+F.toObject(poseidon([ID.toString()]))+'  '+ID.toString());
    console.log("poseidon([ID]): "+F.toObject(poseidon([220421209901010370])));
/*
const msg = F.e(1234);

const prvKey = Buffer.from("fc813aed5ed79547f5b4e0f7708033860a5291e43cf1b7a11592ec911ba141c", "hex");
console.log(prvKey);
// console.log(prvKey.toString('hex'));
console.log('----------------------------------------------');

const pubKey = eddsa.prv2pub(prvKey);
console.log(pubKey);
console.log('----------------------------------------------');

const hexString = Array.prototype.map.call(pubKey[0], (byte) => {
  return ("00" + byte.toString(16)).slice(-2);
}).join("");

console.log(Buffer.from(pubKey[0]).toString('hex'))
console.log(hexString);
console.log('----------------------------------------------');

console.log(eddsa.babyJub.packPoint(pubKey));
console.log('----------------------------------------------');

const signature = eddsa.signPoseidon(prvKey, msg);
console.log(signature);
console.log(signature.S);

console.log('----------------------------------------------');

console.log(eddsa.packSignature(signature));

console.log(Buffer.from(eddsa.packSignature(signature)).toString('hex'));

console.log(eddsa.unpackSignature(eddsa.packSignature(signature)));


console.log(eddsa.verifyPoseidon(msg, signature, pubKey));*/
})();