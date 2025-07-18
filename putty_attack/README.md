Biased Nonce Attack on PuTTY P-521 Signatures

To verify the attack, we used the following implementation:

https://github.com/malb/bdd-predicate.git (commit 142c2f359c3452d44a30c7359e4ae096d2fcaf1a)

from

Martin R. Albrecht and Nadia Heninger. On Bounded Distance Decoding with Predicate: Breaking the "Lattice Barrier" for the Hidden Number Problem. EUROCRYPT 2021. full version available as Cryptology ePrint Archive: Report 2020/1540

The artifacts were produced with the following command:

$ docker run -ti --rm -v `pwd`:/bdd-predicate -w /bdd-predicate martinralbrecht/bdd-predicate sage -python ecdsa_cli.py benchmark -n 521 -k 512 -m 56 -a enum_pred -t 1024 -j 256 

The command is repeated for different values of "-m 56", ranging from 56 to 64. The success rate and computation time can be found in the last line of the output.
Specifically, the success rate is given in the form "sr: 100%". You can use this command line to generate a report:

$ grep sr: *.out | sed -n 's/.*-\([0-9]\+\)\.out.*sr:[^0-9]*\([0-9]\+\)%.*/\1;\2/p'| sort -n
56;0
57;7
58;52
59;94
60;100
61;100
62;100
63;100
64;100

Here are some explanations and hints:

`pwd`: The above command assumes that it is run from within the checked out bdd-predicate repository. If this is not the case, you can replace this with the local path to the repository.
-n 521: This is the required length of the nonce in ECDSA NIST P-521.
-k 512: This is the actual length of the biased nonce in PuTTY.
-m 56: This is the number of signatures available to the attacker.
-a sieve_pred This is the algorithm used to solve the Hidden Number Problem. You can also use enum_pred as an alternative (note that enum_pred will not terminate for small m, I recommend at least 59 for that algorithm).
-t 1024 This is the number of trials to execute.
-j 256 This is the number of parallel trials to execute on a multi-core computer. You can adjust this to the system you are using.

You can repeat the experiment using the following option:
-s NUMBER where NUMBER is the seed from the log file.

 
