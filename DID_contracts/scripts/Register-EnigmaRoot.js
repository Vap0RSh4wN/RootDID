const chai = require("chai");
const fs = require('fs')
const buildEddsa =require("circomlibjs").buildEddsa;
const { Scalar } =require("ffjavascript");
const assert = chai.assert;
const newMemEmptyTrie = require("circomlibjs").newMemEmptyTrie;
const buildPoseidon = require("circomlibjs").buildPoseidon;
const genRandomBabyJubValue = require("./generaate_privatekey");
const prompt = require("prompt-sync")();
var process = require('child_process');
const path = require('path');
const address = require("../deploy/01-deploy");
var createBlakeHash = require('blake-hash');
const { network,ethers, getNamedAccounts } = require("hardhat")
const {JsonRpcProvider} = require("ethers");
const  NewIdentityABI =require("../constants/ContractABI.json").NewIdentity;
const  RegisterABI =require("../constants/ContractABI.json").Register;



function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var createBlakeHash__default = /*#__PURE__*/_interopDefaultLegacy(createBlakeHash);

let provider;
let eddsa;
let poseidon;
let tree;
let F;
const ID = 220421209901010375n;//在input.json中，如果ID外面带引号变成ID字符串和不带引号的ID数字哈希值是不一样的
// const salt = genRandomBabyJubValue();
const salt = 19575205003271201733456932019346756354564123523504998527218008003572080943789n;



function Base24ToDecimalArray(str) {
    const radix = 24;
    const arr = str.split('');
    const decimalArray = arr.map((char) => parseInt(char, radix));
    return decimalArray;
}

function decimalToBase24(decimalNumber) {
    const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    let result = '';
    if (decimalNumber === 0) {
        return '0';
    }
    while (decimalNumber > 0) {
        result = characters[decimalNumber % 24] + result;
        decimalNumber = Math.floor(decimalNumber / 24);
    }
    return result;
}
//传入的是私钥十六进制的字符串，转为BabyJub circom能识别的形式。
async function formatPrivKeyForBabyJub(prv){
    const pruneBuffer=(buff) =>{
        buff[0] = buff[0] & 0xF8;
        buff[31] = buff[31] & 0x7F;
        buff[31] = buff[31] | 0x40;
        return buff;
    }
    const sBuff = pruneBuffer(createBlakeHash__default["default"]("blake512").update(Buffer.from(prv,"hex")).digest());
    let s = Scalar.fromRprLE(sBuff, 0, 32);
    return Scalar.shr(s,3);
}

async function saveEnigma(prvKey0,prvKey1,salt,order){
    let order_Save='';
    for(let i=0;i<24;i++){    
        order_Save+=decimalToBase24(order[i]);
    }
    prvKey0 = prvKey0.toString(16);
    prvKey1 = prvKey1.toString(16);
    salt = salt.toString(16);
    const EnigmaString = `DID-${prvKey0}-${prvKey1}-${salt}-${order_Save}`;
    console.log(`Your Enigma: ${EnigmaString}`);
    try {
        const filePath = path.join(__dirname, '../enigma/Dontloseit_New.txt');
        let data = fs.writeFileSync(filePath, EnigmaString);
        console.log("Saved!");
      } catch (err) {
        console.error(err);
      }
}

async function BinaryConstruct(prvKey0_BigInt,prvKey1_BigInt){
    const prvKey0 = Buffer.from(prvKey0_BigInt.toString(16),"hex");//其值和bigint直接toString()不同
    console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[0]));
    console.log('eddsa.prv2pub(prvKey0): '+F.toString(eddsa.prv2pub(prvKey0)[1]));
    const prvKey1 = Buffer.from(prvKey1_BigInt.toString(16),"hex");
    console.log('eddsa.prv2pub(prvKey1): '+F.toString(eddsa.prv2pub(prvKey1)[0]))
    console.log('eddsa.prv2pub(prvKey1): '+F.toString(eddsa.prv2pub(prvKey1)[1]))
    const signature0 = eddsa.signPoseidon(prvKey0, F.e(ID));//F.e(1234)
    const signature1 = eddsa.signPoseidon(prvKey1, F.e(ID));
    console.log("signature0.R8[0]",F.toObject(signature0.R8[0]));
    console.log("signature0.R8[1]",F.toObject(signature0.R8[1]));
    console.log("signature0.S",signature0.S);
    console.log("signature1.R8[0]",F.toObject(signature1.R8[0]));
    console.log("signature1.R8[1]",F.toObject(signature1.R8[1]));
    console.log("signature1.S",signature1.S);

    var spilt = new Array(12);
    spilt[0] = F.toObject(signature0.R8[0]);
    spilt[1] = F.toObject(signature0.R8[1]);
    spilt[2] = signature0.S;
    spilt[3] = F.toObject(signature1.R8[0]);
    spilt[4] = F.toObject(signature1.R8[1]);
    spilt[5] = signature1.S;
    spilt[6] = F.toString(eddsa.prv2pub(prvKey0)[0]);
    spilt[7] = F.toString(eddsa.prv2pub(prvKey0)[1]);
    spilt[8] = F.toString(eddsa.prv2pub(prvKey1)[0]);
    spilt[9] = F.toString(eddsa.prv2pub(prvKey1)[1]);
    //应该是formatPrivKeyForBabyJub后的私钥
    spilt[10] = await formatPrivKeyForBabyJub(prvKey0_BigInt.toString(16));
    spilt[11] = await formatPrivKeyForBabyJub(prvKey1_BigInt.toString(16));
    console.log("spilt[10]: "+spilt[10]);
    console.log("spilt[11]: "+spilt[11]);


    var binary=new Array(12);
    binary[0] = spilt[0].toString(2).padStart(256, '0');
    binary[1] = spilt[1].toString(2).padStart(256, '0');
    binary[2] = spilt[2].toString(2).padStart(256, '0');//S也是256位，补上的一位0转成十六进制就消失了
    binary[3] = spilt[3].toString(2).padStart(256, '0');
    binary[4] = spilt[4].toString(2).padStart(256, '0');
    binary[5] = spilt[5].toString(2).padStart(256, '0');//S也是256位，补上的一位0转成十六进制就消失了
    binary[6] = BigInt(spilt[6]).toString(2).padStart(256, '0');
    binary[7] = BigInt(spilt[7]).toString(2).padStart(256, '0');
    binary[8] = BigInt(spilt[8]).toString(2).padStart(256, '0');
    binary[9] = BigInt(spilt[9]).toString(2).padStart(256, '0');
    binary[10] = spilt[10].toString(2).padStart(256, '0');
    binary[11] = spilt[11].toString(2).padStart(256, '0');
    return [spilt,binary];
}

async function LeafsConstruct(binary,order){
    var leafpieces = new Array(24);
    var j=0;
        for(let i=0;i<24;i=i+2){
            leafpieces[order[i]] = BigInt('0b' + binary[j].substring(0, 128));
            leafpieces[order[i+1]] = BigInt('0b' + binary[j].substring(128, 256));
            j++;
            console.log("leafpieces[",order[i],"]:",leafpieces[order[i]],"leafpieces[",order[i+1],"]:",leafpieces[order[i+1]])
        }
    var leaf = new Array(4);
    let l0,l1,l2,l3,l4,l5;
    for(let i = 0;i < 4;i++){
        l0 = leafpieces[i*6];
        l1 = leafpieces[i*6+1];
        l2 = leafpieces[i*6+2];
        l3 = leafpieces[i*6+3];
        l4 = leafpieces[i*6+4];
        l5 = leafpieces[i*6+5];
        leaf[i] = poseidon([l0,l1,l2,l3,l4,l5]);
        // console.log("leaf["+i+"] is: "+F.toObject(leaf[i]));
    }
    return leaf;
}

async function treeInsert(tree, _key, _value) {
    const key = F.e(_key);
    const value = F.e(_value)
    const res = await tree.insert(key,value);
    let siblings = res.siblings;
    // console.log(siblings.length)
    for (let i=0; i<siblings.length; i++) siblings[i] = F.toObject(siblings[i]);
    while (siblings.length<2) siblings.push(0);
    // const w = {
    //     fnc: [1,0],
    //     oldRoot: F.toObject(res.oldRoot),
    //     siblings: siblings,
    //     oldKey: res.isOld0 ? 0 : F.toObject(res.oldKey),
    //     oldValue: res.isOld0 ? 0 : F.toObject(res.oldValue),
    //     isOld0: res.isOld0 ? 1 : 0,
    //     newKey: F.toObject(key),
    //     newValue: F.toObject(value)
    // };
    // console.log(w);
}

async function RootConstruct(leaf){
    tree = await newMemEmptyTrie();
    const key0 = F.e(0);
    const value0 = F.e(leaf[0]);
    await treeInsert(tree, key0, value0);
    const key1 = F.e(1);
    const value1 = F.e(leaf[1]);
    await treeInsert(tree, key1, value1);
    const key2 = F.e(2);
    const value2 = F.e(leaf[2]);
    await treeInsert(tree, key2, value2);
    const key3 = F.e(3);
    const value3= F.e(leaf[3]);
    await treeInsert(tree, key3, value3);
    return tree.root;
}

async function generateRoot(){
    const prvKey0 = genRandomBabyJubValue();
    const prvKey1 = genRandomBabyJubValue();
    // const prvKey0 = 9621768605262634734918713082183293757924219030966503451274639623013218319386n;
    // const prvKey1 = 14200607995197972823965731073981021837095956128891777177287223965569684217639n;
    var arr = Array.from({length: 24}, (_, i) => i);
    var order=arr.sort(() => Math.random() - 0.5);
    await saveEnigma(prvKey0.toString(16),prvKey1.toString(16),salt,order);
    let [_,binary] = await BinaryConstruct(prvKey0,prvKey1);
    var leaf = await LeafsConstruct(binary,order);
    var root = await RootConstruct(leaf);
    console.log(F.toObject(root));
    return root;
};

async function loadEnigma(){
    var prvKey0,prvKey1,salt,order;
    const filePath = path.join(__dirname, '../enigma/Dontloseit_New.txt');
    let arr = fs.readFileSync(filePath, 'utf-8').split('-');
    prvKey0 = arr[1];
    prvKey1 = arr[2];
    salt = arr[3];
    order = arr[4];
    let [inputs,binary] = await BinaryConstruct(BigInt('0x'+prvKey0),BigInt('0x'+prvKey1));
    console.log("inputs"+inputs)
    order = Base24ToDecimalArray(order);
    var leaf = await LeafsConstruct(binary,order);
    var root = await RootConstruct(leaf);
    return [salt,inputs,root,order];
    // console.log(F.toObject(root));
   
}

// async function executeCommand(){
//     const commands = [
//         'echo "****GENERATING WITNESS FOR SAMPLE INPUT****"',
//         'start=`date +%s`',
//         'node '+path.join(__dirname, '../build/DID_js/')+'generate_witness.js '+ path.join(__dirname, '../build/DID_js/')+'DID.wasm '+path.join(__dirname, 'input.json')+' '+ path.join(__dirname, '../build/witness.wtns'),
//         'end=`date +%s`',
//         'echo "DONE ($((end-start))s)"',

//         'echo "****GENERATING PROOF FOR SAMPLE INPUT****"',
//         'start=`date +%s`',
//         'snarkjs groth16 prove '+path.join(__dirname, '../build/DID.zkey')+' '+ path.join(__dirname, '../build/witness.wtns')+' '+ path.join(__dirname, '../build/proof.json')+' '+ path.join(__dirname, '../build/public.json'),
//         'end=`date +%s`',
//         'echo "DONE ($((end-start))s)"',

//         'echo "****VERIFYING PROOF FOR SAMPLE INPUT****"',
//         'start=`date +%s`',
//         'snarkjs groth16 verify '+path.join(__dirname, '../build/vkey.json')+' '+ path.join(__dirname, '../build/public.json')+' '+ path.join(__dirname, '../build/proof.json'),
//         'end=`date +%s`',
//         'echo "DONE ($((end-start))s)"',

//         'echo "****GENERATING FINAL SNARK PROOF****"',
//         'cd '+path.join(__dirname, '../build/')+'&&snarkjs generatecall'
//     ]
//     try {
//         for (const command of commands) {
//           const output = process.execSync(command, { encoding: 'utf-8' });
//           console.log(output);
//         }
//       } catch (error) {
//         console.error(`执行命令时发生错误: ${error}`);
//       }
// }

async function ProofFormat2Solidity(proof){
    const regex = /"([^"]*)"/g;
    const res = proof.match(regex).map(match => match.slice(1, -1));
    // var proof = new Array(3);
    // proof[0]=[res[0],res[1]];
    // proof[1]=[[res[2],res[3]],[res[4],res[5]]];
    // proof[2]=[res[6],res[7]];
    //单引号变成双引号。
    //使用 JSON.stringify 方法将数组转换为 JSON 字符串，这样所有的字符串都会被双引号包裹。然后你可以通过去除首尾的方括号来得到纯粹的双引号包裹的字符串。
    // const jsonString = JSON.stringify(res.slice(0,8));
    const result = res.slice(0,8);
    return result;
}

async function SendProofToContract(proof,args){
    console.log("proof"+proof);   
    console.log(...proof);   
    console.log("args"+args);
    console.log(...args);
    // const provider = new ethers.providers.JsonRpcProvider('');
    const UserWallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
    const UserAddress = await UserWallet.getAddress();
    console.log(`Address: ${UserAddress}`);
    const TrustorWallet = new ethers.Wallet('0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a', provider);
    const TrustorAddress = await TrustorWallet.getAddress();
    console.log(`Address: ${TrustorAddress}`);
    
    const NewIdentity = await ethers.getContractAt("NewIdentity", "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",UserWallet);
    
    const res = await NewIdentity.updateIdentity(
        ["0x18dc6e7812d8515f6af6d7470f4b103146a7384856015d23e93e5e4339b792b5", "0x205c71f675b1cbe15179891230597152d89db75899a972e516ce63a3a4b8fd82"],[["0x181ee7148c1b5c4d020fe255c02e980b7baa085eed7e2a36cd66613ceeaa4445", "0x09842e0ae0bfccf347bbe6ed2196638cc2d8f351a10b695ea1cbe2168fe1f626"],["0x28e7f5c06a1d66e6651603f559cb3130e95c3f3351b215b971707cdf50ef78b6", "0x18434c980391cfcaa004fdb2c90ee2c3d6b0070a003d247d889415101da55d76"]],["0x1a6037d27240ba240d3e308ef1c36d96b4c880a0bed15a47a1bd74ac6f239d02", "0x11ecf03e274752303125c19a7805edc3e9b0691cf43617723baff89e8a0c0efa"],["0x2eea18550f1f115d1c392ee2b91697193d0f1e4f7c077ea8f6e305b1268cc85b","0x07c295ffca36e595a7c4a1fa34feb6b6c47f6ac7ba15817cf19f77b0bca1efef","0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266","0x234318a514b299293f538412a278c8c94054a7ef1dc7a8188f5b1c7279290a3a"]
    );
    await res.wait();
    console.log(res);

    // await deployments.fixture(["NewIdentity"]);
    // const NewIdentity = await ethers.getContract("NewIdentity");
    // const NewIdentity = await ethers.getContractAt(
    //     "NewIdentity",
    //     "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    //     address.deployer
    //   );
    //   console.log("NewIdentity: "+NewIdentity);
    //   console.log("NewIdentity.address: "+NewIdentity.address);

    

}

async function executeCommands(index,args) {
    const commands = [
        'echo "****GENERATING WITNESS FOR SAMPLE INPUT****"',
        'start=`date +%s`',
        'node '+path.join(__dirname, '../build/EnigmaRoot_pre/EnigmaRoot_js/')+'generate_witness.js '+ path.join(__dirname, '../build/EnigmaRoot_pre/EnigmaRoot_js/')+'EnigmaRoot.wasm '+path.join(__dirname, '../shell/EnigmaRoot.json')+' '+ path.join(__dirname, '../build/EnigmaRoot_pre/witness.wtns'),
        'end=`date +%s`',
        'echo "DONE ($((end-start))s)"',

        'echo "****GENERATING PROOF FOR SAMPLE INPUT****"',
        'start=`date +%s`',
        'snarkjs groth16 prove '+path.join(__dirname, '../build/EnigmaRoot_pre/EnigmaRoot.zkey')+' '+ path.join(__dirname, '../build/EnigmaRoot_pre/witness.wtns')+' '+ path.join(__dirname, '../build/EnigmaRoot_pre/proof.json')+' '+ path.join(__dirname, '../build/EnigmaRoot_pre/public.json'),
        'end=`date +%s`',
        'echo "DONE ($((end-start))s)"',

        'echo "****VERIFYING PROOF FOR SAMPLE INPUT****"',
        'start=`date +%s`',
        'snarkjs groth16 verify '+path.join(__dirname, '../build/EnigmaRoot_pre/vkey.json')+' '+ path.join(__dirname, '../build/EnigmaRoot_pre/public.json')+' '+ path.join(__dirname, '../build/EnigmaRoot_pre/proof.json'),
        'end=`date +%s`',
        'echo "DONE ($((end-start))s)"',

        'echo "****GENERATING FINAL SNARK PROOF****"',
        'cd '+path.join(__dirname, '../build/EnigmaRoot_pre/')+'&&snarkjs generatecall'
    ]
  
    const command = commands[index];
    //递归执行每条命令
    process.exec(command, async (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }
      if(stdout!=='')console.log(stdout);
      if(stderr!=='')console.error(`stderr: ${stderr}`);
      if(stdout!==''&&index == commands.length-1) {
        console.log('All commands executed');
        var res = await ProofFormat2Solidity(stdout);
        var proof = [
            [res[0],res[1]],
            [[res[2],res[3]],[res[4],res[5]]],
            [res[6],res[7]]
        ]
        await SendProofToContract(proof,args);
        
        return;
    }
      await executeCommands(index + 1,args);
    });
}

async function generateSig_from_Owner_or_AssciatedAddress(newRoot){
    const Owner_assciated_Wallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
    const Owner_assciated_Address = await Owner_assciated_Wallet.getAddress();
    console.log(`Address: ${Owner_assciated_Address}`);
    const message = '0x' +F.toObject(newRoot).toString(16).padStart(64, '0');
    const sig = await Owner_assciated_Wallet.signMessage(message);
    return sig.toString();
}

async function generateProof(inputs,oldRoot,newRoot,HashedID,order){
     // Prepare circuit input
     const UserWallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
     const UserAddress = await UserWallet.getAddress();
     const input = {
        // Public inputs
        "OldRoot":[F.toObject(oldRoot).toString()],
        "HashedID":[HashedID.toString()],
        "NewOwner":[UserAddress.toString()],
        "NewRoot":[F.toObject(newRoot).toString()],
        //private inputs
        "SIG0":inputs.slice(0, 3).map((element) => {
            return String(element);
          }),
        "SIG1":inputs.slice(3, 6).map((element) => {
            return String(element);
          }),
        "ID":[ID.toString()],
        "Salt":[salt.toString()],
        "PrivKey0":[inputs[10].toString()],
        "PrivKey1":[inputs[11].toString()],
        "order":order.map((element) => {
            return String(element);
          }),
    }
    console.log(JSON.stringify(input));
    // Save the inputs in a file
    fs.writeFile(path.join(__dirname, 'input.json'), JSON.stringify(input), function (err) {
        if (err) throw err;
        console.log('Circom Input Loaded!');
        });

    var args = [
        '0x' +F.toObject(oldRoot).toString(16).padStart(64, '0'),
        '0x' +HashedID.toString(16).padStart(64, '0'),
        UserAddress.toString(),
        '0x' +F.toObject(newRoot).toString(16).padStart(64, '0'),
        generateSig_from_Owner_or_AssciatedAddress(newRoot),
    ]
    // const jsonString = JSON.stringify(args);
    // args = jsonString.slice(1, -1).split(",");
    console.log("args: "+args);

    console.log('Generating SNARK proof');

    //递归执行生成proof的每条命令
    await executeCommands(0,args);
}

async  function init(){
    eddsa = await buildEddsa();
    F = eddsa.babyJub.F;
    poseidon = await buildPoseidon();
    provider = new JsonRpcProvider ('http://127.0.0.1:8545/'); 
}

async function main(){
    await init();
    let decison = prompt('  generateRoot and CreateIdentity => 1 \n  LoadEnigma and ChangeIdentity => 2\nPlease input your decision: \n');
    if(decison == 1){
        //注册
        //产生Enigma并且生成root
        let oldRoot = await generateRoot();
        //产生HashedID
        const HashedID = F.toObject(poseidon([poseidon([ID]),salt.toString()]));//最后别忘了加盐，再思考一下这里的盐是什么
        console.log("HashedID: "+HashedID);
        //在Register合约中，用户和信托人都要签名，所以要分别用两个钱包
        const UserWallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        const UserAddress = await UserWallet.getAddress();
        console.log(`UserAddress: ${UserAddress}`);
        const TrustorWallet = new ethers.Wallet('0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a', provider);
        const TrustorAddress = await TrustorWallet.getAddress();
        console.log(`TrustorAddress: ${TrustorAddress}`);
        const RegisterByUser = await ethers.getContractAt("Register", "0x5FbDB2315678afecb367f032d93F642f64180aa3",UserWallet);
        const RegisterByTrustor = await ethers.getContractAt("Register", "0x5FbDB2315678afecb367f032d93F642f64180aa3",TrustorWallet);
        //构造参数
        const _hashedID = '0x' +HashedID.toString(16).padStart(64, '0');
        const _root = '0x' +F.toObject(oldRoot).toString(16).padStart(64, '0');
        //调用Register合约进行多签名，把hash和root存进合约
        //随后由信托人发送至NewIdentity合约的createIdentity函数注册
        const SignByUser = await RegisterByUser.SignByUser(_hashedID,_root);
        await SignByUser.wait();
        const SignByTrustor = await RegisterByTrustor.SignByTrustor(_hashedID,"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512");
        await SignByTrustor.wait();

        console.log("Enigma is saved in Dontloseit_New.txt!");
        console.log("Identity is created!")

    }else if(decison == 2){
        //上面已经注册完毕了
        //用户想更改自己的Enigma、root、DID对应的账户
        //输入自己的Enigma
        let [salt,inputs,oldRoot,order] = await loadEnigma();//获得构建零知识证明的input
        const HashedID = F.toObject(poseidon([poseidon([ID]),BigInt('0x'+salt).toString()]));//最后别忘了加盐，再思考一下这里的盐是什么
        console.log("HashedID: "+HashedID);

        //获得新的root
        let newRoot = await generateRoot();
        //生成proof
        await generateProof(inputs,oldRoot,newRoot,HashedID,order);
        //发送到合约里进行验证

        console.log("New Enigma is saved in Dontloseit_New.txt!");
        console.log("Identity is changed!")
     }
}
main();