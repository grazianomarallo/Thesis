Command line used to find this crash:

/home/ubuntu/afl/afl-fuzz -i /home/ubuntu/Thesis/fuzzer_result/10_05_2019/11:41:52/input -o /home/ubuntu/Thesis/fuzzer_result/10_05_2019/11:41:52/output /home/ubuntu/Thesis/iwd-gm/unit/test-eapol @@

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 50.0 MB.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
