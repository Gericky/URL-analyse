# extract.py
with open('./processed/CSIC-2010/total/attack_urls.txt', 'r', encoding='utf-8') as fin:
    lines = [next(fin) for _ in range(1000)]
with open('./processed/CSIC-2010/part/attack-1000.txt', 'w', encoding='utf-8') as fout:
    fout.writelines(lines)