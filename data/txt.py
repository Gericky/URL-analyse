# extract.py
with open('./processed/CSIC-2010/total/normal_urls.txt', 'r', encoding='utf-8') as fin:
    lines = [next(fin) for _ in range(100)]
with open('./processed/CSIC-2010/part/normal-100.txt', 'w', encoding='utf-8') as fout:
    fout.writelines(lines)