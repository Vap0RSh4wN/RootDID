const { hashPersonalMessage, ecsign } = require("@ethereumjs/util");
const { computeEffEcdsaPubInput } = require("@personaelabs/spartan-ecdsa");


const getEffEcdsaCircuitInput = (privKey, msg) => {
    const msgHash = hashPersonalMessage(msg);
    const { v, r: _r, s } = ecsign(msgHash, privKey);
    const r = BigInt("0x" + _r.toString("hex"));

    const circuitPubInput = computeEffEcdsaPubInput(r, v, msgHash);
    const input = {
        s: BigInt("0x" + s.toString("hex")),
        Tx: circuitPubInput.Tx,
        Ty: circuitPubInput.Ty,
        Ux: circuitPubInput.Ux,
        Uy: circuitPubInput.Uy
    };

    return input;
};
