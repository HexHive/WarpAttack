# WarpAttack: Bypassing CFI through Compiler-Introduced Double-Fetches
WarpAttack is a new attack vector that exploits compiler-introduced double-fetch
optimizations to mount TOCTTOU attacks and bypass code-reuse mitigations. 

See our [paper](http://hexhive.epfl.ch/publications/files/23Oakland3.pdf) for more details.

Citing WarpAttack:
```
@inproceedings{xu2023warpattack,
  title={WarpAttack: Bypassing CFI through Compiler-Introduced Double-Fetches},
  author={Jianhao Xu and Luca Di Bartolomeo and Flavio Toffalini and Bing Mao and Mathias Payer},
  booktitle={2023 IEEE Symposium on Security and Privacy},
  year={2023},
  organization={IEEE}
}
```
## Gadget code detection
We provide a lightweight [binary analysis tool](./gadget_detection/gadget.py) based on Radare2 to detect WarpAttack gadgets. 

Prerequisites
- Python 3.6 or later. You can download from the [official website](https://www.python.org/downloads/). 
- Radare2. You can download the latest version of Radare2 from the [official website](https://rada.re/n/)
- Python packages. You can get all the packages through `pip install r2pipe click bisect`.

Usage
- To use this script, you need to provide a list of input files to be analyzed via stdin. The input files should be separated by space or newlines. You can use the following command to run the script:
```
cat input_files.txt | python3 gadget.py output_file.txt
```
Another example to analyze all possible executable files under one folder:
```
find path/to/target_folder -type f ! -size 0 -exec grep -IL . "{}" \; | python3 gadget.py output_file.txt
```

## Proof of Concept exploit
To get arbitrary Read&Write, we introduce an out-of-bound bug to Firefox 106.0.1 
inspired from one [CTF challenge](https://devcraft.io/2018/04/27/blazefox-blaze-ctf-2018.html). Please find the patch [here](./poc_exploit/blaze.patch).

We also provide a [web page](./poc_exploit/warpattack1a.html) containing malicious [JS code](./poc_exploit/warpattack1a.js). The exploit will be 
triggered when the web page is accessed with the vulnerbale Firefox browser.
