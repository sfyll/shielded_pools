pragma circom 2.1.6;

include "circomlib/bitify.circom";
include "circomlib/escalarmulfix.circom";
include "circomlib/babyjub.circom";

template PedersenCommitment(n) {
    signal input message;
    signal input salt;
    signal output pedersen_commitment[2];

    //base generator of babyjub, can we use it or is it a security hole?
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // //second generator for salt in commitments, taken from: https://iden3-docs.readthedocs.io/en/latest/_downloads/a04267077fb3fdbf2b608e014706e004/Ed-DSA.pdf
    var GENERATOR_H[2] = [
        17777552123799933955779906779655732241715742912184938656739573121738514868268, 
        2626589144620713026669568689430873010625803728049924121243784502389097019475
    ];

    //scalar mult is performed on bitwise representation & we will perform 6 (3 and 3) scalar mults
    component num2Bits_message = Num2Bits(n);
    component num2Bits_salt = Num2Bits(n);
    component escalarMultFix_message = EscalarMulFix(n, BASE8);
    component escalarMultFix_salt = EscalarMulFix(n, GENERATOR_H);

    //as such, we constraint two bitwise representation of the message and the salt
    num2Bits_message.in <== message;
    num2Bits_salt.in <== salt;

    //we now perform our two scalar mults
    var bits;
    for(bits = 0; bits<n; bits++) {
        escalarMultFix_message.e[bits] <== num2Bits_message.out[bits];
    }
    
    for(bits = 0; bits<n; bits++) {
        escalarMultFix_salt.e[bits] <== num2Bits_salt.out[bits];
    }

    //We constraint two cyphers, in the form of elliptic curve points, to be the output of the scalar mults
    signal cypher_message[2];
    cypher_message[0] <== escalarMultFix_message.out[0];
    cypher_message[1] <== escalarMultFix_message.out[1];

    signal cypher_salt[2];
    cypher_salt[0] <== escalarMultFix_salt.out[0];
    cypher_salt[1] <== escalarMultFix_salt.out[1];

    //we perform a babyAdd over the message and salt to get the pedersen commitment
    component babyAdd = BabyAdd();
    babyAdd.x1 <== cypher_message[0];
    babyAdd.y1 <== cypher_message[1];
    babyAdd.x2 <== cypher_salt[0];
    babyAdd.y2 <== cypher_salt[1];

    pedersen_commitment[0] <== babyAdd.xout;
    pedersen_commitment[1] <== babyAdd.yout;
}

