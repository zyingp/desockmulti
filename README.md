# desockmulti
A de-socketing tool that is 10x faster than [desock (Preeny)](https://github.com/zardus/preeny) in fuzzing network protocols

# Build
`make`

# Usage
Similar to desock (Preeny):

`USE_RAW_FORMAT=1 LD_PRELOAD=/path/to/desockmulti/desockmulti.so ./afl-fuzz -d -i testcase_dir -o findings_dir -- /path/to/program [...params...]`

`USE_RAW_FORMAT=1` is telling desockmulti that the seed is in orginal format, but not the new multifuzz format (checking our MultiFuzz paper if you are interested, and the source code of MultiFuzz is here https://github.com/hdusoftsec/MultiFuzz).

# Documentation
Please check the Section 4.4 of our MultiFuzz paper, which can be downloaded from https://www.mdpi.com/1424-8220/20/18/5194/pdf .

If you use desockmulti, please kindly help to cite our paper: 

Yingpei Zeng, Mingmin Lin, Shanqing Guo, Yanzhao Shen, Tingting Cui, Ting Wu, Qiuhua Zheng, Qiuhua Wang, MultiFuzz: A Coverage-Based Multiparty-Protocol Fuzzer for IoT Publish/Subscribe Protocols, Sensors, Vol.20, No.18, 5194, 2020.
