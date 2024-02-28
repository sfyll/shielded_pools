pragma circom 2.1.6;

include "circomlib/comparators.circom";
include "pedersen_commitment.circom";

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
