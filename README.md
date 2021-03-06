# Identifying Software and Protocol Vulnerabilities in WPA2 Implementations through Fuzzing

# User Manual


- [Description](#description)
- [Goals](#goals)
- [Project Structure](#project-structure)
- [Building Project](#builgind-project)
- [Testing](#testing)
- [Author](#author)
- [Contributors](#contributors)

## Description

Nowadays many activities of our daily lives are essentially based on the Internet. Information and services are available at every moment and they are just a click
away. Wireless connections, in fact, have made these kinds of activities faster
and easier. Nevertheless, security remains a problem to be addressed. If it is compromised, you can face severe consequences. When connecting to a protected
Wi-Fi network a handshake is executed that provides both mutual authentication
and session key negotiation. A recent discovery proves that this handshake is vulnerable to key reinstallation attacks. In response, vendors patched their implementations to prevent key reinstallations (KRACKs). However, these patches are non-trivial,
and hard to get correct. Therefore it is essential that someone audits these patches to assure that key reinstallation attacks are indeed prevented.

More precisely, the state machine behind the handshake can be fairly complex. On top of that, some implementations contain extra code to deal with Access Points that do not properly follow the 802.11 standard. This further complicates an implementation of the handshake. All combined, this makes it difficult to reason about the correctness of a patch. This means some patches may be flawed in practice.

There are several possible techniques that can be used to accomplish this kind of analysis such as: formal verification, fuzzing, code audits, etc. Among all of these, software fuzzing is, de facto, one of the most popular vulnerability discovery solutions and for this reason has been selected. Feasibility and methodology on how to fuzz an open-source implementation with a goal to detect potential flaws will be discussed and presented. The goal of this thesis is then to define whether it is possible to detect software bugs in a protocol implementation, including protocol- level vulnerabilities like KRACK, using a systematic approach and in an automated way.



## Goals

- Identify software bugs in a protocol implementation using a systematic approach and in automated way

- Identify protocol-level vulnerabilities, like KRACK, exploiting fuzzer analysis

- Devise a generalised methodology to apply automated vulnerability detection to cryptographic protocol implementations


## Project Structure

* **iwd-gm**: iNet Wirless Deamon implmentation 
    * Link to Github repo: [https://git.kernel.org/pub/scm/network/wireless/iwd.git/]
    * Link to Wiki [https://wiki.archlinux.org/index.php/Iwd]

* **iwd-gm-cov**: modified version of the iwd-gm used to perform coverage analysis

* **ell**: library dependency that iwd has. ell provides D-Bus, Netlink, Main event loop, Timers, and various primitives for iwd. Forked from [https://git.kernel.org/pub/scm/libs/ell/ell.git]

* **fuzzer\_result**: stores the results folder created by AFL after the execution

* **data\_message**: stores the Eapol-data frames used to run tests

* **utils**: stores utility code used to create input file for AFL

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 

### Prerequisites

Linux based machine is required to allow the functioning of the bash script created and for the correct functioning of both AFL and iwd. It's possible to find the specs used for carrying out tests in this work in the box below. We suggest to have a similar configuration to obtain similar results.

```
OS -> Linux Ubuntu
Version -> 16.04.6 LTS (Xenial Xerus)
Architecture -> x86 64
ArchiteCPU op-mode(s) -> 64-bit
CPU(s) -> 16
Thread(s) per core -> 1
Model name -> Intel Core Processor (Broadwell, IBRS)
CPU MHz -> 2399.994
```

### Installing

The project can be installed and build directly using the provided `initialise.sh` bash script.
Run the bash script `initialise.sh` in order to clone and install on your machine:

* **afl**

* **afl-cov**: (used for coverage metrics)
When the script has completed everything should be up and running.
The script automatically build all the source code inside the `iwd-gm` folder.

Run the following command:

```bash
$ cd Thesis
$ ./initialised.sh
```
## Running the tests

Once AFL and iwd have been correctly configured, it's possible to run test by issuing the following command:

```bash
$ cd Thesis
$ ./start_fuzzing.sh
```
The bash script will automatically create a directory in the fuzzer\_result directory, with the current time in order to be distinguished from the other. The data-frame used to run the test is coded into the script itself. To provide a different data-frame is necessary to give the name and the path where it is located. It's sufficient to create a copy of the desidered data-frame and locate into the data\_message folder. The script will retrieve it automatically and pass it to the fuzzer.
The script provide different options (showed when executed without any parameters) that can be used to perform different type of analysis based on different function, different compilation (see for reference [http://lcamtuf.coredump.cx/afl/README.txt] for more info ).

An example running is showed below

```bash
$ ./start_fuzzing.sh -p -t "example message"
```
This command will start an istance of the fuzzer using the function correspondent to the `-p` parameter (ptk_function), `-t` plus a message in quotes to add notes for that kind of execution .

![fuz_ptk](https://user-images.githubusercontent.com/33572242/65053629-830eee80-d96c-11e9-941a-4e6cc272f765.png)

The image above shows how the AFL is presentend to the user. The GUI is divided in different box covering different important information that should be checked during the execution. For further reference to this check the link above

### Running Code Coverage tests

It's possible to run additional test on the results obtained by AFL using a companion tool called `afl-cov` (see here for more [https://github.com/mrash/afl-cov]). It is already installed and working for our project. To perform the analysis we are requested to make a copy of the target code that we have analysed with AFL and compile it with the the predifined option:

```bash
$ cp iwd-gm iwd-gm-cov
```
Then in iwd-gm-cov/Makefile of the project we need to change the compilation option with: `gcc -fprofile-arcs -ftest-coverage`.

After all these steps are done it is possible to use the script bash stored under the fuzzer\_result directory. It will be enough to run the script to automatically retrieve all the information needed to the lcov to perform its analysis. 

```bash
$ cd fuzzer\_result
$ ./start_coverage.sh -d dd_mm_yyyy/ptk/hh:mm:ss
```
Once the tool has completed in the corresponde folder passed as parameter, under [...]/cov/ it will be possible to access the different xml file generated showing the coverage obtained. An example is showed in the image below

![ptk_coverage](https://user-images.githubusercontent.com/33572242/65053700-a3d74400-d96c-11e9-8ad4-5e084b160980.png)


### Plot data results

To plot the result of a specific results it is possible to use afl-plot tool, already installed with this project.
It is needed to go in the result folder that need to be plotted and issue the command showed in the example below:

```bash
$ cd fuzzer\_result/31_05_2019/ptk_gtk/08:01:00/output
$ afl-plot . out_plot
```
The images below show the three different plot that it is possible to build starting from the results obtained by AFL during the execution.

![exec_speed](https://user-images.githubusercontent.com/33572242/65053730-b2256000-d96c-11e9-80fa-931d9812c83a.png)


![high_freq1](https://user-images.githubusercontent.com/33572242/65053785-cff2c500-d96c-11e9-84da-2743c70cf6c5.png)
![low_freq1](https://user-images.githubusercontent.com/33572242/65053786-d08b5b80-d96c-11e9-9c9b-d0b976c346f9.png)

### Crash Database & Exploitable

Along with all the other tool available in this project it is possible to add another one to allow a better view of the crashes. afl-collect (see here for reference [https://github.com/rc0r/afl-utils]) and Exploitable (see here for reference [https://github.com/jfoote/exploitable]) can be used to copy all crash sample files from an afl synchronisation directory (used by multiple afl instances when run in parallel) into a single location providing easy access for further crash analysis.
The installation of this is left to the source page, in our project can be used as follow:

```bash
$ afl-collect -d db_storage/ptk_crashes.db -e  gdb_script 
~/Thesis/fuzzer_result/29_05_2019/ptk/13:52:39 
~/collections/ptk -j 8 -- ~/Thesis/iwd-gm/unit/test-eapol
```

The image below shows an example of the result after the execution of the command.

![gdb_expl](https://user-images.githubusercontent.com/33572242/65053855-e9940c80-d96c-11e9-96c1-e16310965cec.png)

Providing a db extension file where to store our crashes and using exploitable to make crash sample removing and and executing gdb script to evaluate the severity of the bugs found.



## Author

* **Graziano Marallo** - - [grazianomarallo](https://github.com/grazianomarallo)
* Master Thesis @Polito, developed at @KULeuven.

## Contributors



* **Polito Supervisor**: Antonio Lioy
 
* **KU Leuven Supervisors**: Jan Tobias Müehlberg, Mathy Vanhoef


