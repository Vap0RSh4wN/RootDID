var EC = require("elliptic").ec;
const { privateToAddress,hashPersonalMessage, ecsign} = require( "ethereumjs-util");
const { computeEffEcdsaPubInput } =require("@personaelabs/spartan-ecdsa");

const { toBigIntBE } =require('bigint-buffer');
const ec = new EC("secp256k1");



const getEffEcdsaCircuitInput = (privKey, msg) => {
  const msgHash = hashPersonalMessage(msg);
  const { v, r: _r, s } = ecsign(msgHash, privKey);
  const r = BigInt("0x" + _r.toString("hex"));

  const circuitPubInput = computeEffEcdsaPubInput(r, BigInt(v), msgHash);
  const input = {
    s: BigInt("0x" + s.toString("hex")),
    Tx: circuitPubInput.Tx,
    Ty: circuitPubInput.Ty,
    Ux: circuitPubInput.Ux,
    Uy: circuitPubInput.Uy
  };

  return input;
};
  
(async ()=>{
    const privKey = Buffer.from(
        "59f6fc9a90ecf400c87556acc406dcddc705b86da29e3a986b564a3236516813",
        "hex"
      );
    //   const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();
      const addr = BigInt(
        "0x" + privateToAddress(privKey).toString("hex")
      ).toString(10);;
      console.log('Address:',addr);
  
      const msg = Buffer.from("hello world");
      const circuitInput = getEffEcdsaCircuitInput(privKey, msg);
  
      console.log(circuitInput);
})();