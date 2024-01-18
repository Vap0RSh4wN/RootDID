const { network, ethers } = require("hardhat");
module.exports = async ({ getNamedAccounts, deployments }) => {
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();
  // module.exports.deployer = deployer;
  const _trustors = ['0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC','0x90F79bf6EB2c4f870365E785982E1f101E93b906'];
  const _adminers = ['0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65','0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc'];
  
  const args1=[
    _trustors,
    _adminers
  ];

  const Register=await deploy("Register", {
    from:deployer,
    args:args1,
    log:true,
    waitConfirmations: network.config.blockConfirmations || 1,
});

  console.log("Register's address:", Register.address);


  const NewIdentity = await deploy("NewIdentity", {
    from:deployer,
    args:[Register.address],
    log:true,
    waitConfirmations: network.config.blockConfirmations || 1,
  });

  console.log("NewIdentity's address:", NewIdentity.address);
  console.log("deployer's address:", deployer);

  module.exports.deployer = deployer;
}

module.exports.tags = ["all", "deploy"];
