const utils = require('ffjavascript').utils;
const Scalar = require('ffjavascript').Scalar;

const buildBabyjub = require("circomlibjs").buildBabyjub;

const buildEddsa = require("circomlibjs").buildEddsa;
var createBlakeHash = require('blake-hash');
function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var createBlakeHash__default = /*#__PURE__*/_interopDefaultLegacy(createBlakeHash);

let babyJub;
let eddsa;
(async () => {
eddsa = await buildEddsa();
babyJub = await buildBabyjub();


//        const prvKey = crypto.randomBytes(32);

const prvKey = Buffer.from("fc813aed5ed79547f5b4e0f7708033860a5291e43cf1b7a11592ec911ba141c","hex");
// const prvKey = fromHexString("0001020304050607080900010203040506070809000102030405060708090001");
console.log(prvKey);
var privKey=7138197988445191036766446983677074043860026322671030693397041628770238862364n;
privKey = BigInt(privKey.toString())
const bigInt2Buffer = (i) => {
    return Buffer.from(i.toString(16), 'hex')
}
console.log(eddsa.prv2pub(bigInt2Buffer(privKey)))
// console.log('---'+utils.leBuff2int(Buffer.from(eddsa.prv2pub(bigInt2Buffer(privKey))[0])));
// console.log('---'+utils.leBuff2int(Buffer.from(eddsa.prv2pub(bigInt2Buffer(privKey))[1])));

const pruneBuffer=(buff) =>{
    buff[0] = buff[0] & 0xF8;
    buff[31] = buff[31] & 0x7F;
    buff[31] = buff[31] | 0x40;
    return buff;
}
const formatPrivKeyForBabyJub = (prv) => {
    const sBuff = pruneBuffer(createBlakeHash__default["default"]("blake512").update(Buffer.from(prv,"hex")).digest());
    let s = Scalar.fromRprLE(sBuff, 0, 32);
    return Scalar.shr(s,3);
}
// const formatPrivKeyForBabyJub = (privKey) => {
    
//     const sBuff = pruneBuffer(
//         createBlakeHash("blake512").update(
//             bigInt2Buffer(privKey),
//         ).digest().slice(0,32)
//     )
//     const s = utils.leBuff2int(sBuff)
//     return babyJub.mulPointEscalar(babyJub.Base8, Scalar.shr(s,3));
// }
console.log('---'+formatPrivKeyForBabyJub("2b542b85723c427b3ab199e291e0404146e9d4dcfbb5d07c7a833773e03bcc8b"))
console.log('---'+formatPrivKeyForBabyJub("fc813aed5ed79547f5b4e0f7708033860a5291e43cf1b7a11592ec911ba141c").toString())
console.log(Buffer.from("2b542b85723c427b3ab199e291e0404146e9d4dcfbb5d07c7a833773e03bcc8b","hex"))
a=19598168015318048359024826852643115473975305615283742173675185034454764342411n;
console.log(Buffer.from(a.toString()))


const F = eddsa.babyJub.F;
console.log(F.e("17541829991279967606368379727798038755181031262040940908351409534254002800859"))
console.log(F.toString(eddsa.prv2pub(bigInt2Buffer(privKey))[0]));


const pubKey = eddsa.prv2pub(prvKey);
console.log(pubKey);
console.log('----------------------------------------------');
// console.log(utils.leBuff2int(Buffer.from(pubKey[0])));
// console.log(Buffer.from(pubKey[1]).toString('hex'));
console.log('----------------------------------------------');

const pPubKey = babyJub.packPoint(pubKey);
console.log(pPubKey);



// const keypair = new Keypair()
// console.log(keypair.privKey.asCircuitInputs());

// const circuitInputs = stringifyBigInts({
//     'privKey': keypair.privKey.asCircuitInputs(),
// })

// const witness = await genWitness(circuit, circuitInputs)

// const derivedPubkey0 = await getSignalByName(circuit, witness, 'main.pubKey[0]')
// const derivedPubkey1 = await getSignalByName(circuit, witness, 'main.pubKey[1]')
// expect(derivedPubkey0).toEqual(keypair.pubKey.rawPubKey[0].toString())
// expect(derivedPubkey1).toEqual(keypair.pubKey.rawPubKey[1].toString())
})();