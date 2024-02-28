pragma circom 2.1.6;

include "circomlib/bitify.circom";
include "circomlib/escalarmulfix.circom";
include "circomlib/babyjub.circom";
include "circomlib/comparators.circom";

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

template CheckHomomorphism(n) {
    signal input message_a;
    signal input message_b;
    signal input salt_a;
    signal input salt_b;
    signal output pedersen_commitment[2];

    signal message_c <== message_a + message_b;
    signal salt_c <== salt_a + salt_b;

    component pedersen_commitment_a = PedersenCommitment(n);
    pedersen_commitment_a.message <== message_a;
    pedersen_commitment_a.salt <== salt_a;

    component pedersen_commitment_b = PedersenCommitment(n);
    pedersen_commitment_b.message <== message_b;
    pedersen_commitment_b.salt <== salt_b;
    
    component pedersen_commitment_c = PedersenCommitment(n);
    pedersen_commitment_c.message <== message_c;
    pedersen_commitment_c.salt <== salt_c;
    pedersen_commitment <== pedersen_commitment_c.pedersen_commitment;

    //we perform a babyAdd over our addition members (a and b), to be able to test for homomorphism
    component cypher_a_plus_b = BabyAdd();
    cypher_a_plus_b.x1 <== pedersen_commitment_a.pedersen_commitment[0];
    cypher_a_plus_b.y1 <== pedersen_commitment_a.pedersen_commitment[1];
    cypher_a_plus_b.x2 <== pedersen_commitment_b.pedersen_commitment[0];
    cypher_a_plus_b.y2 <== pedersen_commitment_b.pedersen_commitment[1];

    //we then perform an equality check over the two points, which would verify the homomorphic
    //properties of pedersen commitments, namely f(a+b) = f(a)+f(b)
    component isEqual[2];
    isEqual[0] = IsEqual();
    isEqual[0].in[0] <== cypher_a_plus_b.xout;
    isEqual[0].in[1] <== pedersen_commitment[0];

    isEqual[1] = IsEqual();
    isEqual[1].in[0] <== cypher_a_plus_b.yout;
    isEqual[1].in[1] <== pedersen_commitment[1];

    isEqual[0].out === 1;
    isEqual[1].out === 1;

    log("cypher_a_plus_b.xout: ", cypher_a_plus_b.xout);
    log("pedersen_commitment[0]", pedersen_commitment[0]);
    log("cypher_a_plus_b.yout: ", cypher_a_plus_b.yout);
    log("pedersen_commitment[1]", pedersen_commitment[1]);
}

component main = CheckHomomorphism(252);

/* INPUT = {
    "message_a": "5",
    "message_b": "77",
    "salt_a": "55830285329582903859084109851409851905890158091253810589201581290",
    "salt_b": "55830285329582903859084109851409851905890158091253810589201581530"
} */
