const { ethers } = require('ethers');

// 创建一个钱包
const privateKey = '0x59f6fc9a90ecf400c87556acc406dcddc705b86da29e3a986b564a3236516813'; // 你的私钥
const wallet = new ethers.Wallet(privateKey);

const message = '0x000423f1b97b47dbaf3206d5861aa11fcdc7b4800f55dbe174f1b4d7607d84a0'; // 要签名的消息
var sig;
(async()=>{
  // const sigg = wallet.signMessage(message).then((signature) => {
  //   // 计算消息的哈希值
  //   const messageHash = ethers.utils.hashMessage(message);
  //   // 转换为eth签名的消息哈希值
  // //   const ethSignedMessageHash = ethers.utils.arrayify(messageHash);
  
  //   console.log('Signature:', signature);
  //   console.log("messageHash:", messageHash);
  // });
  // sig=await sigg;
  sig = await wallet.signMessage(message);
  
  console.log(sig.toString());
})();

