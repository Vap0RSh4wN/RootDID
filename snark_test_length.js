const {utils} = require('ffjavascript')
const crypto = require('crypto')
const { bigInt } = require('snarkjs');

const rbigint = nbytes => utils.leBuff2int(crypto.randomBytes(nbytes))
const deposit = { nullifier: rbigint(31), secret: rbigint(31) }
deposit.preimage = Buffer.concat([utils.leInt2Buff(deposit.nullifier), utils.leInt2Buff(deposit.secret)])
console.log(deposit.preimage)

/** BigNumber to hex string of specified length */
function toHex(number, length = 32) {
    const str = number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)
    return '0x' + str.padStart(length * 2, '0')
  }

const note = toHex(deposit.preimage, 62)
console.log(note)
const s=crypto.randomBytes(3)
console.log(s)
console.log(utils.leBuff2int(s))