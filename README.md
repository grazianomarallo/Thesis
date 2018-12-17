# Security Analysis of the WPA2 KRACK patches

Master's Thesis @Polito, developed at @KULeuven.
Polito Supervisor: Antonio Lioy
KU Leuven Supervisors: Jan Tobias Muehlberg, Mathy Vanhoef

- [Description](#description)
- [Goals](#goals)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Author](#author)

## Description

Recently have been discovered that WPA2 is vulnerable to key
reinstallation attacks (KRACKs). In response, software vendors patched their
implementations to prevent key reinstallations. However, how can we be sure
those patches are correct, and indeed prevent all key reinstallations? What if
they are flawed, and it is still possible to attack implementations? In this
thesis this questions will be addressed, and perform a security analysis of
patches that are supposed to prevent key reinstallation attacks. Fuzzing technique
will be applied in order to perform severl analysis.

- _Context_:  When connecting to a protected Wi-Fi network, a handshake is
executed that provides both mutual authentication and session key negotiation.
Recently, we discovered that this handshake is vulnerable to key reinstallation
attacks. In response, vendors patched their implementations to prevent key
reinstallations. However, these patches are non-trivial, and hard to get
correct. Therefore it is essential that someone audits these patches to assure
that key reinstallation attacks are indeed prevented.

More precisely, the state machine behind the handshake can be fairly complex. On
top of that, some implementations contain extra code to deal with Access Points
that do not properly follow the 802.11 standard. This further complicates an
implementation of the handshake. All combined, this makes it difficult to
reason about the correctness of a patch, meaning some patches may be flawed in
practice.


## Goals

The goal of this thesis is to asses the correctness of patches. By doing that 
different analysis will be done in order to find several bugs and possibile bug
patterns in the 4-way Handshake implementation.


## Project Structure

- iwd-gm (forked from git://git.kernel.org/pub/scm/network/wireless/iwd.git)

- ell (forked from git://git.kernel.org/pub/scm/libs/ell/ell.git)

- fuzzer\_result: store the the result of the fuzzer executions

- Report: store the slideshow and the final report developed so far

- start\_fuzzing.sh: bash script used in order to start the fuzzer

## Testing

```bash
$ cd <home_dir>
$ ./start_fuzzing.sh
```
The bash script will create a directory in /tmp (called fuzzer\_result), which will contain a directory with
the current date and time of creation. The so created folder will store both input and output for the current execution.
The input folder is loaded statically at the moment with significant test data. 
(Future work add new input seeds to the script)



## Author

* **Graziano Marallo** - *Initial work* - [grazianomarallo](https://github.com/grazianomarallo)

