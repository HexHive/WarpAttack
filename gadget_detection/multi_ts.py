import os

import sys
import re
import r2pipe
from bisect import bisect_left
import logging

def run_r2(binary_name):
    logging.warning(f"\x1b[1mOpening {binary_name} ...\x1b[0m")
    try:
        r = r2pipe.open(binary_name)
    except:
        return []
    r.cmd("e asm.lines = 0") # disable ascii lines
    r.cmd("e asm.bytes = 0") # disable raw bytes
    r.cmd("e asm.hints = 0") # disable hints
    r.cmd("e asm.offset = 0") # disable display of addr
    r.cmd("e asm.comments = 0") # disable comments
    r.cmd("e asm.var = 0") # disable comments

    final_result = []
    final_result2 = []
    # sum = 0
    for i,reg in enumerate(["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]):
        r.cmd(f"/a jmp {reg}")
        r.cmd(f"f~hit{i}")
        indjmps = str(r.cmd(f"f~hit{i}")).split("\n")[:-1]
        indjmps = [s.split(' ')[0] for s in indjmps] # only addr
        indjmps = list(dict.fromkeys(indjmps)) # remove redundant addr
        for addr in indjmps:
            r.cmd(f"s {addr}")
            prev_lines = str(r.cmd("pd -10")).split("\n")[:-1]
            cur_line   = str(r.cmd("pd 1")).split("\n")[-2]
            cur_line_hg = f"\x1b[33m{cur_line}\x1b[0m"
            prev_lines_hg = ""
            mems = []
            for line in prev_lines:
                mem = re.findall(r'\[.*]', line)
                if len(mem) >= 1:
                    prev_lines_hg += f"\x1b[98;1m{line}\x1b[0m\n"
                    mems += mem
                else:
                    prev_lines_hg += f"\x1b[90m{line}\x1b[0m\n"
            
            for m in set(mems):
                if mems.count(m) >= 2: # TODO or may be 1 is enough
                    fetch_idx = []
                    jt_cal_idx = -1
                    # cmp_idx = -1
                    for i, line in enumerate(prev_lines):
                        if line.find(m) != -1:
                            fetch_idx.append(i)
                        if len(re.findall(r'\[.*[+-].*\*[0-9]*\]',line)):
                            jt_cal_idx = i
                            # just need the last one 
                    # jump table pattern
                    if jt_cal_idx != -1 and len(re.findall(reg, prev_lines[jt_cal_idx])) == 2:
                        # the second fetch is a load
                        # reg is used at least once between [2nd fetch, the calculation [a+b*n]), but not a cmp
                        # there is a cmp between [1st fetch, 2nd fetch), cmp can be [cmp, sub, test, and+xor, dec] call？
                        # two fetches should in the same function
                        if jt_cal_idx > fetch_idx[-1] and prev_lines[fetch_idx[-1]].find('mov') != -1 \
                            and prev_lines[fetch_idx[-1]].find('],') == -1 \
                            and len(re.findall(r'[re][abcds][xi]', prev_lines[fetch_idx[-1]])) \
                            and ''.join(prev_lines[fetch_idx[-1]:jt_cal_idx]).find(reg[1:]) != -1 \
                            and len(re.findall(r'cmp[ ]*[re]' + reg[1:], ''.join(prev_lines[fetch_idx[-1]:jt_cal_idx]))) == 0\
                            and len(re.findall('(?:cmp|sub|test|and|shl|sal|rol|dec)', ''.join(prev_lines[fetch_idx[-2]:fetch_idx[-1]])))\
                            and len(re.findall('(?:push rbp|ret)', ''.join(prev_lines[fetch_idx[-2]:fetch_idx[-1]]))) == 0:
                            if prev_lines[fetch_idx[-2]].find('],') != -1 and prev_lines[fetch_idx[-2]].find('cmp') == -1:
                                df_type = 'f->s->f'
                            else:
                                df_type = 'f->f'
                            win_len = str(fetch_idx[-1] - fetch_idx[-2] + 1) + '-long'
                            if len(re.findall('(?:jmp|call)', ''.join(prev_lines[fetch_idx[-2]:fetch_idx[-1]]))):
                                win_len = win_len + ' with j/c'
                            logging.info(f"\x1b[32mPossible {df_type} ({win_len}) of {m} at {addr}:\x1b[0m")
                            final_result2 += ["%s - Possible switch found" % (addr)]
                            logging.info(prev_lines_hg.strip())
                            logging.info(cur_line_hg)
                            break
            else:
                continue

    return list(dict.fromkeys(final_result2))

log_filename = sys.argv[1] if len(sys.argv) > 1 else "example.log"
logging.basicConfig(filename=log_filename, encoding='utf-8', level=logging.DEBUG)
file_list = list(sys.stdin)
file_list = [l.strip() for l in file_list]
all_result = []
df_count = 0
for f in file_list:
    r = run_r2(f)
    if len(r):
        df_count += len(r)
        all_result.append((f, r))
logging.warning("Summary: Found in %d files with %d reports" % (len(all_result), df_count))
for f, r in all_result:
    r = [rr.split(' ')[0] for rr in r]
    logging.warning(f"In {f}: {str(r)}")
