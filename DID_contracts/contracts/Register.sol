// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.11;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IdentityManagementContract {
    function createIdentity(bytes32 _hashedID, address _owner, bytes32 _root) external;
    // function verifySignature_external(bytes32 message, bytes memory sig) external pure returns (address);
    function getOwner(bytes32 _hashedID) external view returns (address);
    function changeRoot_ByTrustor(bytes32 _hashedID, address _owner, bytes32 _root) external;
}

contract Register is ReentrancyGuard {
    struct registerInfo {
        bytes32 root;
        bytes32 hashedID;
        bool active;
    }

    struct changeInfo {
        bytes32 root;
        bytes32 hashedID;
    }
    // bool active;

    IdentityManagementContract identity_management;
    mapping(address => registerInfo) register;
    mapping(address => changeInfo) changer;
    mapping(address => bool) public Trustor;
    mapping(address => bool) public Admin;
    address IdentityManagement_address;

    //**************************************************************
    // Event definitions
    //**************************************************************

    event UserRegistered(bytes32 indexed hashedID, address user, bytes32 root);
    event UserChangeRoot(bytes32 indexed hashedID, address user, bytes32 newroot);
    event TrustorSigned(bytes32 indexed hashedID, address user, bool active, address trustor);
    event ChangeRoot_TrustorSigned(bytes32 indexed hashedID, address user, bytes32 newroot, address trustor);
    event TrustorAdded(address trustor);
    event TrustorDisabled(address trustor);
    event AdminAdded(address admin);
    event AdminDisabled(address admin);

    constructor(address[] memory _trustors, address[] memory _admins, address _IdentityManagement_address) {
        for (uint256 i = 0; i < _trustors.length; i++) {
            Trustor[_trustors[i]] = true;
        }
        for (uint256 i = 0; i < _admins.length; i++) {
            Admin[_admins[i]] = true;
        }
        IdentityManagement_address = _IdentityManagement_address;
    }

    modifier onlyAdmin() {
        require(Admin[msg.sender] == true, "Only the admin can call this function");
        _;
    }

    modifier onlyTrustor() {
        require(Trustor[msg.sender] == true, "Only the trustor can call this function");
        _;
    }

    //保证address和root是用户自己加的
    function SignByUser(bytes32 _hashedID, bytes32 _root) external nonReentrant {
        // if(_hashedID.length != 32) {
        //     revert("The length of hashedID is not 32!");
        // }

        //active的address不可以再调用。

        if (register[msg.sender].active == true) {
            revert("The address has been registered!");
        }
        if (register[msg.sender].hashedID.length != 32 || register[msg.sender].root.length != 32) {
            revert("The length of hashedID or root is not 32!");
        }

        register[msg.sender].hashedID = _hashedID;
        register[msg.sender].root = _root;
        emit UserRegistered(_hashedID, msg.sender, _root);
    }

    //root信user，hash和active信trustor

    //根据用户hash后的ID和给定的地址，找到用户的address和root并确认未被注册，然后调用IdentityManagement合约的createIdentity注册
    //保证active的最后署名是government加的
    function SignByTrustor(bytes32 _hashedID, address _user) external onlyTrustor nonReentrant {
        if (register[_user].hashedID != _hashedID) {
            revert("The hashedID has not registered!");
        }
        if (register[_user].root == "") {
            revert("The root has not registered!");
        }
        //防止government作恶，覆盖某用户的address和root
        if (register[_user].active == true) {
            revert("The hashedID has been registered!");
        }
        if (register[_user].hashedID.length != 32 || register[_user].root.length != 32) {
            revert("The length of hashedID or root is not 32!");
        }
        register[_user].active = true;
        //send tx to identity contract
        identity_management = IdentityManagementContract(IdentityManagement_address);
        identity_management.createIdentity(_hashedID, _user, register[_user].root);
        emit TrustorSigned(_hashedID, _user, register[_user].active, msg.sender);
    }

    //如果用户enigma丢失，用户需在gov端重新验证身份后，在此函数中输入新root，当前hashedID对应的Owner需要是msg.sender
    function ChangeRoot_SignByUser(bytes32 _hashedID, bytes32 _newroot) external nonReentrant {
        identity_management = IdentityManagementContract(IdentityManagement_address);
        address owner = identity_management.getOwner(_hashedID);
        require(msg.sender == owner, "The msg.sender is not Owner!");
        changer[msg.sender].hashedID = _hashedID;
        changer[msg.sender].root = _newroot;
        emit UserChangeRoot(_hashedID, msg.sender, _newroot);
    }

    //trustor检查到UserChangeRoot事件被身份验证后的owner和_hashedID触发后，帮助用户调用此函数，完成root的更改
    function ChangeRoot_SignByTrustor(bytes32 _hashedID, address _user) external onlyTrustor nonReentrant {
        if (changer[_user].hashedID != _hashedID) {
            revert("The hashedID has not inputed!");
        }
        if (changer[_user].root == "") {
            revert("The root has not inputed!");
        }
        if (changer[_user].hashedID.length != 32 || changer[_user].root.length != 32) {
            revert("The length of hashedID or root is not 32!");
        }

        identity_management = IdentityManagementContract(IdentityManagement_address);
        identity_management.changeRoot_ByTrustor(_hashedID, _user, changer[_user].root);

        delete changer[_user].hashedID;
        delete changer[_user].root;
        emit ChangeRoot_TrustorSigned(_hashedID, _user, changer[_user].root, msg.sender);
    }

    function getRegister(address _user) external view returns (registerInfo memory) {
        return register[_user];
    }

    function addTrustor(address[] calldata _newtrustor) external onlyAdmin nonReentrant {
        for (uint256 i = 0; i < _newtrustor.length; i++) {
            Trustor[_newtrustor[i]] = true;

            emit TrustorAdded(_newtrustor[i]);
        }
    }

    function disableTrustor(address[] calldata _trustor) external onlyAdmin nonReentrant {
        for (uint256 i = 0; i < _trustor.length; i++) {
            Trustor[_trustor[i]] = false;

            emit TrustorDisabled(_trustor[i]);
        }
    }

    function addAdmin(address[] calldata _newadmin) external onlyAdmin nonReentrant {
        for (uint256 i = 0; i < _newadmin.length; i++) {
            Admin[_newadmin[i]] = true;

            emit AdminAdded(_newadmin[i]);
        }
    }

    function disableAdmin(address[] calldata _admin) external onlyAdmin nonReentrant {
        for (uint256 i = 0; i < _admin.length; i++) {
            Admin[_admin[i]] = false;

            emit AdminDisabled(_admin[i]);
        }
    }

    /// @dev DON'T give me your money.
    fallback() external {}
}
