pragma solidity ^0.8.0;
contract VerifySignature{
    function get_message_hash(address _to, uint _amount, string memory _msg, uint _nonce) public pure returns (bytes32){
        return keccak256(abi.encodePacked(_to,_amount,_msg,_nonce));
    }
    function get_signed_messagedhash(bytes32 _messagehash) public pure returns(bytes32){
        return keccak256(abi.encodePacked("signed message\n:",_messagehash));
    }
    function recoversigner(bytes32 _ethsignedmessagehash, bytes memory _signature) public pure returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v)= splitSignature(_signature);
        return ecrecover(_ethsignedmessagehash, v, r, s);
    }
    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v){
        require(sig.length== 65, 'invalid message length');
         assembly {
            /*
            First 32 bytes stores the length of the signature
            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature
            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

    }
    function verify(address _signer, address _to, string memory _message, uint _amount, uint256 _nonce, bytes memory signature)public pure returns(bool){
        bytes32 messagehash= get_message_hash(_to, _amount, _message , _nonce);
        bytes32 ethsignedmessagehash= get_signed_messagedhash(messagehash);
        return recoversigner (ethsignedmessagehash, signature)== _signer;
    }
    
    
}
//This needs to be clear and understandable
