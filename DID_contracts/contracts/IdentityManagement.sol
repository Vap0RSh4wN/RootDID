// SPDX-License-Identifier: GPL-3.0
// 本合约实现功能：createIdentity 和SMT交互 验证所有的零知识证明电路  key recovery 所有的功能都在本合约
pragma solidity ^0.8.11;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./IdentityTree.sol";
import "./Verify_CertificateIssuance.sol";
import "./Verify_ChangeDowner.sol";
import "./Verify_EnigmaRoot.sol";
import "./Verify_RevocationDowner.sol";
import "./Verify_VC_predicate.sol";
import "./Verify_VC_without_predicate.sol";
import {PoseidonUnit2L, PoseidonUnit3L} from "./iden3lib/Poseidon.sol";

// import "poseidon-sol/Poseidon.sol";

contract IdentityManagement is ReentrancyGuard {
    struct Identity {
        // uint256 DID;
        address owner;
        bytes32 root;
        address[5] recoveryAddress;
        mapping(bytes32 => bool) used;
        // mapping(address => bool) blackLists;
        mapping(address => uint256) ownerHistory;
        address[] ownerKeys;
    }
    //成为法官的权利，可以disable其他的地址。这个权利只有在使用enigma更新的address才能拥有，并且只能使用一次。防止日后这个账户的私钥被盗，盗窃者使用这个账户非法disable其他地址。
    // bool judge;
    //被设置为true后，该账户所做的任何操作都会使其变回false

    Verify_CertificateIssuance public immutable verify_certificateissuance;
    Verify_EnigmaRoot public immutable verify_enigmaroot;
    Verify_ChangeDowner public immutable verify_changeDowner;
    Verify_RevocationDowner public immutable verify_revocationDowner;
    Verify_VC_predicate public immutable verify_VC_predicate;
    Verify_VC_without_predicate public immutable verify_VC_without_predicate;

    mapping(bytes32 => Identity) internal identities;

    address public register;
    IdentityTree public identityTree;
    uint256 internal Index = 0;

    //**************************************************************
    // Event definitions
    //**************************************************************

    event IdentityCreated(bytes32 indexed hashedID, address owner, bytes32 root);
    event IdentityCreatChanged(bytes32 indexed hashedID, address newOwner, bytes32 newRoot);
    event RootChanged_EnigmaLost(bytes32 indexed hashedID, address owner, bytes32 newRoot);

    constructor(address _register, address _identityTree) {
        bytes32 _salt = keccak256(abi.encodePacked(msg.sender, block.timestamp)); //这是部署合约的时候生成的salt，用于create2
        verify_certificateissuance = new Verify_CertificateIssuance{salt: _salt}();
        verify_enigmaroot = new Verify_EnigmaRoot{salt: _salt}();
        verify_changeDowner = new Verify_ChangeDowner{salt: _salt}();
        verify_revocationDowner = new Verify_RevocationDowner{salt: _salt}();
        verify_VC_predicate = new Verify_VC_predicate{salt: _salt}();
        verify_VC_without_predicate = new Verify_VC_without_predicate{salt: _salt}();

        register = _register;
        identityTree = IdentityTree(_identityTree);
    }

    modifier onlyRegister() {
        require(msg.sender == register, "Only the register contract can call this function");
        _;
    }

    modifier Owner_or_RecoveryAddress(bytes32 _hashedID) {
        bool pass = false;
        //owner?
        if (msg.sender == identities[_hashedID].owner) {
            pass = true;
        } else {
            //RecoveryAddress?
            for (uint256 i = 0; i < identities[_hashedID].recoveryAddress.length; i++) {
                if (msg.sender == identities[_hashedID].recoveryAddress[i]) {
                    pass = true;
                    break;
                }
            }
        }

        require(pass, "Only the owner or associated address can call this function");
        _;
    }

    //createIdentity中同一个hashedID只能被register调用一次
    //本函数front runner高gas攻击依然安全，因为只有register能够调用本函数，并且owner和root值register无法自己指定。
    //这里onlyRegister是指只有这个合约能够调用本函数。
    function createIdentity(
        bytes32 _hashedID,
        // uint256 _DID,
        address _owner,
        bytes32 _root
    ) external onlyRegister nonReentrant {
        _root = avoidOverflowAttack(_root);
        if (identities[_hashedID].owner != address(0)) {
            revert("Identity already exists");
        }
        if (_hashedID.length != 32 || _root.length != 32) {
            revert("The length of hashedID or root is not 32!");
        }
        // console.logBytes32(_hashedID);
        // console.log(_owner);
        // console.logBytes32(_root);
        identities[_hashedID].owner = _owner; //注册owner
        //owner加入ownerHistory，记录时间戳
        identities[_hashedID].ownerHistory[_owner] = block.timestamp;
        identities[_hashedID].ownerKeys.push(_owner);

        identities[_hashedID].root = _root; //注册root
        identities[_hashedID].used[_root] = false; //标注root未使用

        //向HashedID_Tree添加新的叶子节点。
        identityTree.add(
            false, Index, PoseidonUnit3L.poseidon([uint256(_hashedID), uint256(uint160(_owner)), uint256(_root)])
        );
        Index++; //Index累加

        emit IdentityCreated(_hashedID, _owner, _root);
    }

    function changeRoot_ByTrustor(
        bytes32 _hashedID,
        // uint256 _DID,
        address _owner,
        bytes32 _root
    ) external onlyRegister nonReentrant {
        if (identities[_hashedID].owner != _owner) {
            revert();
        }
        identities[_hashedID].used[identities[_hashedID].root] = true; //把以前的old root置为使用过
        identities[_hashedID].root = _root; //更新root
        identities[_hashedID].used[_root] = false; //标注new root未使用

        emit RootChanged_EnigmaLost(_hashedID, _owner, _root);
    }

    function createRecoveryAddress(bytes32 _hashedID, address _address)
        external
        Owner_or_RecoveryAddress(_hashedID)
        nonReentrant
    {
        require(identities[_hashedID].recoveryAddress.length < 5, "The number of associated address is up to 5");
        identities[_hashedID].recoveryAddress[identities[_hashedID].recoveryAddress.length] = _address;
    }

    function changeOwner(bytes32 _hashedID, address _address)
        external
        Owner_or_RecoveryAddress(_hashedID)
        nonReentrant
    {
        //如果将owner转移给old owner，那么不可以重置其时间
        //以下if为true时代表这个_address不在ownerHistory中，需要将其加入ownerHistory并设置时间
        if (identities[_hashedID].ownerHistory[_address] == 0) {
            identities[_hashedID].ownerHistory[_address] = block.timestamp;
            identities[_hashedID].ownerKeys.push(_address);
        }
        //如果本来就在ownerHistory中，那么不需要重置时间
        identities[_hashedID].owner = _address;
    }

    function changeRecoveryAddress(bytes32 _hashedID, uint256 index, address _address)
        external
        Owner_or_RecoveryAddress(_hashedID)
        nonReentrant
    {
        require(index < 5, "The index is between 0~4");
        identities[_hashedID].recoveryAddress[index] = _address;
    }

    //用于解决RecoveryAddress被盗并更改owner的情况。此时攻击者并不掌握current owner的私钥，只能把当前owner换为新的恶意owner。
    //这也就使得恶意owner创建时间晚，可以被早期的owner恢复。删除恶意associated address。只能删除创建时间较晚的ownerHistory中的恶意owner。
    function recoveryByOwnerHistory(bytes32 _hashedID, address[] memory _disableAddress, bool _deleteRecoveryAddress)
        external
        nonReentrant
    {
        //如果msg.sender在ownerHistory中且时间比owner早，那么可以恢复owner
        require(
            identities[_hashedID].ownerHistory[msg.sender] != 0
                && identities[_hashedID].ownerHistory[msg.sender]
                    < identities[_hashedID].ownerHistory[identities[_hashedID].owner],
            "msg.sender not in ownerHistory or the time is later than current owner"
        );
        identities[_hashedID].owner = msg.sender;
        //是否删除恶意的associated address
        if (_deleteRecoveryAddress) {
            delete identities[_hashedID].recoveryAddress;
        }
        //将恶意的地址们从ownerHistory中删除
        if (_disableAddress[0] != address(0)) {
            for (uint256 i = 0; i < _disableAddress.length; i++) {
                //如果msg.sender的时间比_disableAddress时间早，那么可以删除该_disableAddress
                //这意味着recoveryByOwnerHistory机制下，owner history永远不会被删空，给原始owner恢复余地。
                if (
                    identities[_hashedID].ownerHistory[msg.sender]
                        < identities[_hashedID].ownerHistory[_disableAddress[i]]
                ) {
                    // 删除mapping中的键值对
                    delete identities[_hashedID].ownerHistory[
                        _disableAddress[i]
                    ];
                    // 删除数组中对应的元素
                    delete identities[_hashedID].ownerKeys[
                        getRecoveryAddressIndex(
                            _hashedID,
                            _disableAddress[i]
                        )
                    ];
                }
            }
        }
    }

    //********************************************************************* */

    //From: https://learnblockchain.cn/2019/10/16/bytes-to-uint/#:~:text=Solidity%20%E4%B8%AD%20bytes%E7%B1%BB%E5%9E%8B%E5%A6%82%E4%BD%95%E8%BD%AC%E6%8D%A2%E4%B8%BA%E6%95%B4%E5%9E%8B%20uint%20bytes%E7%B1%BB%E5%9E%8B%E5%A6%82%E4%BD%95%E8%BD%AC%E6%8D%A2%E4%B8%BA%E6%95%B4%E5%9E%8B%20uint%20function%20bytesToUint,%28b.length-%20%28i%2B1%29%29%29%29%3B%20%7D%20return%20number%3B%20%7D%20%E5%AD%A6%E5%88%86%3A%2025
    //convert bytes to uint256

    function bytesToUint256(bytes memory b) public pure returns (uint256) {
        uint256 number;
        for (uint256 i = 0; i < b.length; i++) {
            number = number + uint8(b[i]) * (2 ** (8 * (b.length - (i + 1))));
        }
        return number;
    }

    //From: https://stackoverflow.com/questions/67893318/solidity-how-to-represent-bytes32-as-string
    //Author: Mikhail Vladimirov
    //convert bytes32 to string

    function toHex16(bytes16 data) internal pure returns (bytes32 result) {
        result = (bytes32(data) & 0xFFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000)
            | ((bytes32(data) & 0x0000000000000000FFFFFFFFFFFFFFFF00000000000000000000000000000000) >> 64);
        result = (result & 0xFFFFFFFF000000000000000000000000FFFFFFFF000000000000000000000000)
            | ((result & 0x00000000FFFFFFFF000000000000000000000000FFFFFFFF0000000000000000) >> 32);
        result = (result & 0xFFFF000000000000FFFF000000000000FFFF000000000000FFFF000000000000)
            | ((result & 0x0000FFFF000000000000FFFF000000000000FFFF000000000000FFFF00000000) >> 16);
        result = (result & 0xFF000000FF000000FF000000FF000000FF000000FF000000FF000000FF000000)
            | ((result & 0x00FF000000FF000000FF000000FF000000FF000000FF000000FF000000FF0000) >> 8);
        result = ((result & 0xF000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000) >> 4)
            | ((result & 0x0F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F00) >> 8);
        result = bytes32(
            0x3030303030303030303030303030303030303030303030303030303030303030 + uint256(result)
                + (
                    ((uint256(result) + 0x0606060606060606060606060606060606060606060606060606060606060606) >> 4)
                        & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
                ) * 7
        );
    }

    function toHex(bytes32 data) internal pure returns (string memory) {
        return string(abi.encodePacked("0x", toHex16(bytes16(data)), toHex16(bytes16(data << 128))));
    }

    //********************************************************************* */
    //From: https://github.com/WeBankBlockchain/SmartDev-Contract/blob/master/contracts/base_type/string/LibString.sol
    //convert string to Lower case

    function toLowercase(string memory src) internal pure returns (string memory) {
        bytes memory srcb = bytes(src);
        for (uint256 i = 0; i < srcb.length; i++) {
            bytes1 b = srcb[i];
            if (b >= "A" && b <= "Z") {
                b |= 0x20;
                srcb[i] = b;
            }
        }
        return src;
    }

    //********************************************************************* */
    //From: https://github.com/WeBankBlockchain/SmartDev-Contract/blob/778e66d50d38469fc58b7bfa40d86140f2fcda5d/contracts/business_template/gov_office/utils/TypeConvertUtil.sol#L80
    //convert uint to string

    function uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    //********************************************************************* */

    function verifySignature_external(bytes32 message, bytes memory sig) external pure returns (address) {
        return verifySignature(toLowercase(toHex(message)), sig);
    }

    function verifySignature(string memory message, bytes memory sig) internal pure returns (address) {
        bytes32 messageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(message).length), message));
        bytes32 r;
        bytes32 s;
        uint8 v;

        // 检查签名字节。如果不是65个字节，返回“0”。
        if (sig.length != 65) {
            return (address(0));
        }

        // 分割签名字节
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            // solium-disable-next-line arg-overflow
            return ecrecover(messageHash, v, r, s);
        }
    }

    function avoidOverflowAttack(bytes32 root) internal pure returns (bytes32) {
        uint256 bn128_Prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return bytes32(uint256(root) % bn128_Prime);
    }

    //用户自行更新自己的identity或者更新enigma
    //如果owner私钥被盗，甚至ownerHistory中最初始的owner私钥被盗，那么只能通过updateIdentity的enigma重新获取DID控制权
    //并且删除被盗的和恶意的ownerHistory中的地址，以及删除恶意的associated address
    function updateIdentity(
        uint256[2] calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2] calldata _proofC,
        bytes32 _root,
        bytes32 _hashedID,
        address _newowner,
        bytes32 _newroot,
        bytes memory _sig,
        address[] memory _disableAddress,
        bool _deleteRecoveryAddress
    ) external nonReentrant {
        // console.log(_proofA[0]);
        // console.log(_proofA[1]);
        // console.log(_proofB[0][0]);
        // console.log(_proofB[0][1]);
        // console.log(_proofB[1][0]);
        // console.log(_proofB[1][1]);
        // console.log(_proofC[0]);
        // console.log(_proofC[1]);
        // console.logBytes32(_root);
        // console.log(_root.length);
        // console.logBytes32(_hashedID);
        // console.log(_hashedID.length);
        // console.log(_newowner);
        // console.logBytes32(_newroot);
        // console.logBytes(_sig);
        // console.log(verifySignature(toLowercase(toHex(_newroot)), _sig));

        //防止CVE-2023-33252 overflow double pay attack
        _root = avoidOverflowAttack(_root);
        _newroot = avoidOverflowAttack(_newroot);

        require(
            _root.length == 32 && _hashedID.length == 32 && _newroot.length == 32,
            "The length of root or hashedID or newroot is not 32!"
        );

        require(identities[_hashedID].root == _root, "Root does not match the root of the identity");
        require(_newroot != _root, "The new root can not be the same as the old root");

        //所有输入过的root和newroot不能有重复。
        //并且直接存储root和newroot而不存储proofA和B是为了防止groth16扩展攻击
        require(!identities[_hashedID].used[_root], "Root is used");
        require(!identities[_hashedID].used[_newroot], "Newroot is used"); //newroot不能为之前用过的root

        require( //这样能够保证恶意的owner在把自己DID名誉搞臭后恶意转给无辜的人。
            //并且也能防止有front runner以高gas fee抢先把DID转给别人。
            //_newowner可以等于当前owner，实现owner能够定期更新自己的enigma。
            _newowner == msg.sender,
            "The identity can not be transferred to another address"
        );

        //每次的sig必须不同,防止重放攻击
        //签名者的地址必须为owner history中的地址
        //convert _newroot to lower case string, with sig to get the signer address
        //because _newroot never repeat, also the sig never repeat to avoid replay attack
        //_newroot和sig永远都不会重复，防止重放攻击。
        require(
            identities[_hashedID].ownerHistory[verifySignature(toLowercase(toHex(_newroot)), _sig)] != 0,
            "Signature is not valid"
        );

        require(
            verify_enigmaroot.verifyProof(
                _proofA,
                _proofB,
                _proofC,
                [uint256(_root), uint256(_hashedID), uint256(uint160(_newowner)), uint256(_newroot)]
            ),
            "Proof is not valid"
        );

        //将恶意的地址们从ownerHistory中删除
        //使用enigma的newowner在本函数内可以删除除自己任何地址，但是只能删除一次。
        if (_disableAddress[0] != address(0)) {
            for (uint256 i = 0; i < _disableAddress.length; i++) {
                if (_disableAddress[i] != msg.sender) {
                    // 删除mapping中的键值对
                    delete identities[_hashedID].ownerHistory[
                        _disableAddress[i]
                    ];
                    // 删除数组中对应的元素
                    delete identities[_hashedID].ownerKeys[
                        getRecoveryAddressIndex(
                            _hashedID,
                            _disableAddress[i]
                        )
                    ];
                }
            }
        }
        //是否删除恶意的associated address
        if (_deleteRecoveryAddress) {
            delete identities[_hashedID].recoveryAddress;
        }
        //如果将newowner存在于owner history，那么不可以重置其时间
        //以下if为true时,代表_newowner不在ownerHistory中，需要将其加入ownerHistory并设置时间
        if (identities[_hashedID].ownerHistory[_newowner] == 0) {
            identities[_hashedID].ownerHistory[_newowner] = block.timestamp;
            identities[_hashedID].ownerKeys.push(_newowner);
        }

        identities[_hashedID].used[_root] = true; //该root标记为用过
        identities[_hashedID].owner = _newowner;
        identities[_hashedID].root = _newroot;

        emit IdentityCreatChanged(_hashedID, _newowner, _newroot);
    }

    function CertificateIssuance(
        uint256[2] calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2] calldata _proofC,
        bytes32 _DIDRoot,
        bytes32 _HashedIDRoot
    ) external nonReentrant {
        if (uint256(_DIDRoot) != identityTree.getRoot(true) || uint256(_HashedIDRoot) != identityTree.getRoot(false)) {
            revert("Root is Wrong");
        }
        require(
            verify_certificateissuance.verifyProof(
                _proofA, _proofB, _proofC, [uint256(_DIDRoot), uint256(_HashedIDRoot)]
            ),
            "Proof is not valid"
        );
    }

    function VerifyCertificate_without_predicate(
        uint256[2] calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2] calldata _proofC,
        bytes32 _DIDRoot,
        bytes32 _HashedIDRoot,
        bytes32[3] calldata _SIG_issuer,
        bytes32[2] calldata _PK_issuer,
        uint256 _DIDv,
        bytes32[3] calldata _SIG_Downer
    ) external nonReentrant {
        if (uint256(_DIDRoot) != identityTree.getRoot(true) || uint256(_HashedIDRoot) != identityTree.getRoot(false)) {
            revert("Root is Wrong");
        }
        require(
            verify_VC_without_predicate.verifyProof(
                _proofA,
                _proofB,
                _proofC,
                [
                    uint256(_DIDRoot),
                    uint256(_HashedIDRoot),
                    uint256(_SIG_issuer[0]),
                    uint256(_SIG_issuer[1]),
                    uint256(_SIG_issuer[2]),
                    uint256(_PK_issuer[0]),
                    uint256(_PK_issuer[1]),
                    _DIDv,
                    uint256(_SIG_Downer[0]),
                    uint256(_SIG_Downer[1]),
                    uint256(_SIG_Downer[2])
                ]
            ),
            "Proof is not valid"
        );
    }

    function VerifyCertificate_predicate(
        uint256[2] calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2] calldata _proofC,
        bytes32 _DIDRoot,
        bytes32 _HashedIDRoot,
        bytes32[3] calldata _SIG_issuer,
        bytes32[2] calldata _PK_issuer,
        uint256 _DIDv,
        bytes32[3] calldata _SIG_Downer,
        uint256[2] calldata _predicate,
        uint256 _Comparison_object,
        bytes[3] calldata _in_or_notin,
        uint256 _enable_sybli_value,
        bytes32 _sybli_value
    ) external nonReentrant {
        if (uint256(_DIDRoot) != identityTree.getRoot(true) || uint256(_HashedIDRoot) != identityTree.getRoot(false)) {
            revert("Root is Wrong");
        }
        require(
            verify_VC_predicate.verifyProof(
                _proofA,
                _proofB,
                _proofC,
                [
                    uint256(_DIDRoot),
                    uint256(_HashedIDRoot),
                    uint256(_SIG_issuer[0]),
                    uint256(_SIG_issuer[1]),
                    uint256(_SIG_issuer[2]),
                    uint256(_PK_issuer[0]),
                    uint256(_PK_issuer[1]),
                    _DIDv,
                    uint256(_SIG_Downer[0]),
                    uint256(_SIG_Downer[1]),
                    uint256(_SIG_Downer[2]),
                    _predicate[0],
                    _predicate[1],
                    _Comparison_object,
                    bytesToUint256(_in_or_notin[0]),
                    bytesToUint256(_in_or_notin[1]),
                    bytesToUint256(_in_or_notin[2]),
                    _enable_sybli_value,
                    uint256(_sybli_value)
                ]
            ),
            "Proof is not valid"
        );
    }

    function ChangeDowner(
        uint256[2] calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2] calldata _proofC,
        bytes32 _Old_Leaf_Downer,
        bytes32 _New_Leaf_Downer,
        bytes32 _DIDRoot,
        bytes32 _HashedIDRoot,
        uint256 _DID_Key
    ) external nonReentrant {
        if (uint256(_DIDRoot) != identityTree.getRoot(true) || uint256(_HashedIDRoot) != identityTree.getRoot(false)) {
            revert("Root is Wrong");
        }
        require(
            verify_changeDowner.verifyProof(
                _proofA,
                _proofB,
                _proofC,
                [
                    uint256(_Old_Leaf_Downer),
                    uint256(_New_Leaf_Downer),
                    uint256(_DIDRoot),
                    uint256(_HashedIDRoot),
                    _DID_Key
                ]
            ),
            "Proof is not valid"
        );
        identityTree.add(true, _DID_Key, uint256(_New_Leaf_Downer));
    }

    function RevocationDowner(
        uint256[2] calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2] calldata _proofC,
        bytes32 _DIDRoot,
        bytes32 _HashedIDRoot,
        bytes32 _revocation_Hash,
        uint256 _DID_Key
    ) external nonReentrant {
        if (uint256(_DIDRoot) != identityTree.getRoot(true) || uint256(_HashedIDRoot) != identityTree.getRoot(false)) {
            revert("Root is Wrong");
        }
        require(
            verify_revocationDowner.verifyProof(
                _proofA,
                _proofB,
                _proofC,
                [uint256(_DIDRoot), uint256(_HashedIDRoot), uint256(_revocation_Hash), _DID_Key]
            ),
            "Proof is not valid"
        );
        identityTree.add(true, _DID_Key, 0);
    }

    function getOwner(bytes32 _hashedID) external view returns (address) {
        return identities[_hashedID].owner;
    }

    function getRecoveryAddress(bytes32 _hashedID) external view returns (address[5] memory) {
        return identities[_hashedID].recoveryAddress;
    }

    function getOwnerHistory(bytes32 _hashedID) external view returns (address[] memory) {
        return identities[_hashedID].ownerKeys;
    }

    function getRecoveryAddressIndex(bytes32 _hashedID, address _address) internal view returns (uint256 index) {
        for (uint256 i = 0; i < identities[_hashedID].recoveryAddress.length; i++) {
            if (identities[_hashedID].recoveryAddress[i] == _address) {
                index = i;
                return index;
            }
        }
        revert("Index not found!"); // 如果未找到键
    }

    /// @dev DON'T give me your money.
    fallback() external {}
}
