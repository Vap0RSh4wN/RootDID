// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.11;

import {SmtLib} from "./iden3lib/SmtLib.sol";

//This contract came from before modification: https://github.com/iden3/contracts/blob/75185d4fc1be5c0adda913760f9b2521d29dfc41/contracts/test-helpers/SmtLibTestWrapper.sol
contract IdentityTree {
    using SmtLib for SmtLib.Data;

    //DID tree
    SmtLib.Data internal DID_Tree;
    //HashedID tree
    SmtLib.Data internal HashedID_Tree;

    mapping(uint256 => bool) DID_leaf_Deduplication;
    mapping(uint256 => bool) HashedID_leaf_Deduplication;

    constructor(uint256 maxDepth) {
        DID_Tree.initialize(maxDepth);
        HashedID_Tree.initialize(maxDepth);
    }

    function add(bool isDIDTree, uint256 i, uint256 v) public {
        if (isDIDTree) {
            if (v != 0 && DID_leaf_Deduplication[v]) {
                //正常添加leaf，保证leaf的值v不能重复
                revert("DID tree leaf Deduplication!");
            } else if (v == 0) {
                //当v==0时表示删除index为i的leaf值。
                DID_Tree.addLeaf(i, v);
                return;
            }
            DID_Tree.addLeaf(i, v);
            DID_leaf_Deduplication[v] = true;
        } else {
            if (v != 0 && HashedID_leaf_Deduplication[v]) {
                //正常添加leaf，保证leaf的值v不能重复
                revert("HashedID tree leaf Deduplication!");
            } else if (v == 0) {
                //当v==0时表示删除index为i的leaf值。
                HashedID_Tree.addLeaf(i, v);
                return;
            }
            HashedID_leaf_Deduplication[v] = true;
            HashedID_Tree.addLeaf(i, v);
        }
    }

    function getProof(bool isDIDTree, uint256 id) public view returns (SmtLib.Proof memory) {
        if (isDIDTree) {
            return DID_Tree.getProof(id);
        } else {
            return HashedID_Tree.getProof(id);
        }
    }

    function getProofByRoot(bool isDIDTree, uint256 id, uint256 root) public view returns (SmtLib.Proof memory) {
        if (isDIDTree) {
            return DID_Tree.getProofByRoot(id, root);
        } else {
            return HashedID_Tree.getProofByRoot(id, root);
        }
    }

    function getProofByTime(bool isDIDTree, uint256 id, uint256 timestamp) public view returns (SmtLib.Proof memory) {
        if (isDIDTree) {
            return DID_Tree.getProofByTime(id, timestamp);
        } else {
            return HashedID_Tree.getProofByTime(id, timestamp);
        }
    }

    function getProofByBlock(bool isDIDTree, uint256 id, uint256 _block) public view returns (SmtLib.Proof memory) {
        if (isDIDTree) {
            return DID_Tree.getProofByBlock(id, _block);
        } else {
            return HashedID_Tree.getProofByBlock(id, _block);
        }
    }

    function getRootHistory(bool isDIDTree, uint256 start, uint256 length)
        public
        view
        returns (SmtLib.RootEntryInfo[] memory)
    {
        if (isDIDTree) {
            return DID_Tree.getRootHistory(start, length);
        } else {
            return HashedID_Tree.getRootHistory(start, length);
        }
    }

    function getRootHistoryLength(bool isDIDTree) public view returns (uint256) {
        if (isDIDTree) {
            return DID_Tree.getRootHistoryLength();
        } else {
            return HashedID_Tree.getRootHistoryLength();
        }
    }

    function getRoot(bool isDIDTree) public view returns (uint256) {
        if (isDIDTree) {
            return DID_Tree.getRoot();
        } else {
            return HashedID_Tree.getRoot();
        }
    }

    function getRootInfo(bool isDIDTree, uint256 root) public view returns (SmtLib.RootEntryInfo memory) {
        if (isDIDTree) {
            return DID_Tree.getRootInfo(root);
        } else {
            return HashedID_Tree.getRootInfo(root);
        }
    }

    function getRootInfoListLengthByRoot(bool isDIDTree, uint256 root) public view returns (uint256) {
        if (isDIDTree) {
            return DID_Tree.getRootInfoListLengthByRoot(root);
        } else {
            return HashedID_Tree.getRootInfoListLengthByRoot(root);
        }
    }

    function getRootInfoListByRoot(bool isDIDTree, uint256 root, uint256 start, uint256 length)
        public
        view
        returns (SmtLib.RootEntryInfo[] memory)
    {
        if (isDIDTree) {
            return DID_Tree.getRootInfoListByRoot(root, start, length);
        } else {
            return HashedID_Tree.getRootInfoListByRoot(root, start, length);
        }
    }

    function getMaxDepth(bool isDIDTree) public view returns (uint256) {
        if (isDIDTree) {
            return DID_Tree.getMaxDepth();
        } else {
            return HashedID_Tree.getMaxDepth();
        }
    }
}
