var base62 = require("base62/lib/ascii");
 
console.log(base62.encode(999));  // "g7"
console.log(BigInt(base62.decode("52KqlKIUmka8m2iUQAYgoQ4E6uq4Yg6QOM2yqyAKY6C"))); // 999
console.log(9621768605262634734918713082183293757924219030966503451274639623013218319386n)
console.log(base62.encode(9621768605262634734918713082183293757924219030966503451274639623013218319386));  // "g7"
console.log(base62.encode(9621768605262634734918713082183293757924219030966503451274639623013218319386));  // "g7"
x=9621768605262634734918713082183293757924219030966503451274639623013218319386n;
console.log(x.toString(16));  // "g7"
console.log(base62.encode("0x1545ba60e94bce7ac180720570fdbe774c27956edef271bbe21d9f9a80f2fc1a"));  // "g7"

function toBase62(num) {  
    const base = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';  
    let result = '';  
    
    while (num > 0) {  
      result = base.charAt(num % 62) + result;  
      num = Math.floor(num / 62);  
    }  
    
    return result;  
  }  
    
  console.log(toBase62("0x1545ba60e94bce7ac180720570fdbe774c27956edef271bbe21d9f9a80f2fc1a")); // 输出 "M"  
  console.log(toBase62(10000000)); // 输出 "N"

 
  console.log(BigInt("0x1545ba60e94bce7ac180720570fdbe774c27956edef271bbe21d9f9a80f2fc1a"));


