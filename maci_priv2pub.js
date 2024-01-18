// const {Keypair,PrivKey}= require('maci-domainobjs');
// const { stringifyBigInts } = require('maci-crypto');
const {eddsa } = require( 'circomlib');

(async () => {
// const privKey=new PrivKey(7138197988445191036766446983677074043860026322671030693397041628770238862364n);
// const privKey=new PrivKey("7138197988445191036766446983677074043860026322671030693397041628770238862364");

// const keypair = new Keypair(privKey)
// const a=10236626061854654573880870855668390062353345130531740615658212241316654215051n;
// console.log(keypair.privKey);

//-------------------------------------
var p = BigInt("7138197988445191036766446983677074043860026322671030693397041628770238862364")
const bigInt2Buffer = (i) => {
    return Buffer.from(i.toString(16), 'hex')
}
console.log(bigInt2Buffer(p))
console.log(Buffer.from("fc813aed5ed79547f5b4e0f7708033860a5291e43cf1b7a11592ec911ba141c","hex"))
console.log('=='+eddsa.prv2pub(bigInt2Buffer(p)))
//-------------------------------------

// const circuitInputs = stringifyBigInts({
//     'privKey': keypair.privKey.asCircuitInputs(),
// })
// console.log(circuitInputs);
// console.log(keypair.privKey);

// const witness = await genWitness(circuit, circuitInputs)

// const derivedPubkey0 = await getSignalByName(circuit, witness, 'main.pubKey[0]')
// const derivedPubkey1 = await getSignalByName(circuit, witness, 'main.pubKey[1]')
// console.log(keypair.pubKey.rawPubKey[0].toString())
// console.log(keypair.pubKey.rawPubKey[1].toString())
})();