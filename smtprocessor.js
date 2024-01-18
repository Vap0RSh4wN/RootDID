//circomlib/test/smtprocessor.js  https://github.com/iden3/circomlib/blob/master/test/smtprocessor.js
// const chai = require("chai");
// const path = require("path");
// const wasm_tester = require("circom_tester").wasm;
// const F1Field = require("ffjavascript").F1Field;
// const Scalar = require("ffjavascript").Scalar;

const newMemEmptyTrie = require("circomlibjs").newMemEmptyTrie;
const buildPoseidon = require("circomlibjs").buildPoseidon;
const getHashes = require("circomlibjs").buildSMT;



// const assert = chai.assert;
async function testInsert(tree, _key, _value) {
    const key = tree.F.e(_key);
    const value = tree.F.e(_value)


    const res = await tree.insert(key,value);
    let siblings = res.siblings;
    console.log(siblings.length)
    for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
    while (siblings.length<2) siblings.push(0);

    const w = {
        fnc: [1,0],
        oldRoot: tree.F.toObject(res.oldRoot),
        siblings: siblings,
        oldKey: res.isOld0 ? 0 : tree.F.toObject(res.oldKey),
        oldValue: res.isOld0 ? 0 : tree.F.toObject(res.oldValue),
        isOld0: res.isOld0 ? 1 : 0,
        newKey: tree.F.toObject(key),
        newValue: tree.F.toObject(value)
    };

    console.log(tree.F.toObject(res.newRoot));
    console.log(w);
    
}

let tree;
let Fr;

(async () => {

    const {hash0, hash1,F} = await getHashes();

    tree = await newMemEmptyTrie();
    Fr = tree.F;

    const key3 = Fr.e(0);
    const value3 = Fr.e(222);
    await testInsert(tree, key3, value3);

    const key = Fr.e(1);
    const value = Fr.e(222);

    await testInsert(tree, key, value);

    

    const key2 = Fr.e(2);
    const value2 = Fr.e(222);
    await testInsert(tree, key2, value2);

    const key8 = Fr.e(3);
    const value8 = Fr.e(222);
    await testInsert(tree, key8, value8);

    // const key4 = Fr.e(4);
    // const value4 = Fr.e(222);
    // await testInsert(tree, key4, value4);

    // const key5 = Fr.e(5);
    // const value5 = Fr.e(222);
    // await testInsert(tree, key5, value5);

    // const key6 = Fr.e(6);
    // const value6 = Fr.e(222);
    // await testInsert(tree, key6, value6);
    // const key7 = Fr.e(7);
    // const value7 = Fr.e(222);
    // await testInsert(tree, key7, value7);
    // // console.log(tree.F.toObject(hash1(key2,  value2)));
    // // let s=15473027074611130341204183265969556414998111315291235856789029241868284246721n;
    // // let s1=1211115291902638388006498812967140718900885323410921614423721827545908184236n
    let h0=hash1(key3,  value3);
    let h1=hash1(key,  value);
    let h2=hash1(key2,  value2);
    // let h3=hash1(key8,  value8);
    // let h4=hash1(key4,  value4);
    // let h5=hash1(key5,  value5);
    console.log(tree.F.toObject(h1));
    // console.log(tree.F.toObject(h5));


    // let root_h0_h1=hash0(h0,h1);
    // let root_h2_h3=hash0(h2,h3);
    let root_h0_h2=hash0(h0,h2);
    // let root_h1_h3=hash0(h1,h3);
    // let root_h1_h5=hash0(h1,h5);
    // let root_h0_h4=hash0(h0,h4);
    // let root_h2_h4=hash0(h2,h4);

    // let root_h3_h5=hash0(h3,h5);

    // let root_h2_h5=hash0(h2,h5);
    // console.log(tree.F.toObject(root_h2_h4));
    // console.log(tree.F.toObject(root_h1_h5));
    // // console.log(tree.F.toObject(root_h2));
    console.log(tree.F.toObject(root_h0_h2));
    let poseidon = await buildPoseidon();
    console.log(F.one);
    const res = poseidon([key3,value3,1]);
    const res2 = poseidon([key2,value2,1]);
    const s=poseidon([res,res2]);

    console.log(F.toObject(s));
    // console.log(tree.F.toObject(root_h1_h3));
    // console.log(tree.F.toObject(root_h1_h3));

    // console.log(tree.F.toObject(hash0(hash0(root_h0_h4,h2),hash0(root_h1_h5,h3))));
    // console.log(tree.F.toObject(hash0(hash0(root_h0_h4,h2),root_h1_h3)));

    // console.log(tree.F.toObject(hash0(root_h0_h2,root_h1_h3)));
    
    

    // const key1 = Fr.e(3);
    // const value1 = Fr.e(222);
    // await testInsert(tree, key1, value1);
    
    // const key4 = Fr.e(4);
    // const value4 = Fr.e(222);
    // await testInsert(tree, key4, value4);

    // const key5 = Fr.e(5);
    // const value5 = Fr.e(222);
    // await testInsert(tree, key5, value5);

    // const key6 = Fr.e(6);
    // const value6 = Fr.e(222);
    // await testInsert(tree, key6, value6);

    // const key7 = Fr.e(7);
    // const value7 = Fr.e(222);
    // await testInsert(tree, key7, value7);

    // const key8 = Fr.e(8);
    // const value8 = Fr.e(222);
    // await testInsert(tree, key8, value8);
    
    // let poseidon = await buildPoseidon();
    // console.log(poseidon.F.toString(poseidon(key3, value3)))

})();
