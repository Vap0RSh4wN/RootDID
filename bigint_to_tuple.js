function bigint_to_tuple(x) {
    let mod = 2n ** 64n;
    let ret = [0n, 0n, 0n, 0n];

    var x_temp = x;
    for (var idx = 0; idx < ret.length; idx++) {
        ret[idx] = x_temp % mod;
        x_temp = x_temp / mod;
    }
    return ret;
}
r=bigint_to_tuple(BigInt("0x59f6fc9a90ecf400c87556acc406dcddc705b86da29e3a986b564a3236516813",16))
console.log(r)
// 0x2e1e48c14716af93ca8294875f23285ca7e3bf5804087a981480bdfc4f703a93
// 20859898583266786201116645966419198697193232397128414593685856165829266127507
// 718f58817ca1caa5b6503578df0eb14cf6966fff142596bd4014e0e6cfeb3019