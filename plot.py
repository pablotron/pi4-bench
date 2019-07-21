#!/usr/bin/python3

# generate chart.svg for data

import csv
import sys
import os
import re
import numpy as np
import matplotlib.pyplot as plt

def read_csv(path):
  with open(sys.argv[1], newline = '') as fh:
    return list(reversed(list([row for row in csv.DictReader(fh)])))

# check arguments
if len(sys.argv) < 3:
  print("Usage: {} input.csv output.svg title xlimit".format(sys.argv[0]))
  exit(-1)

# read csv
rows = read_csv(sys.argv[1])

# sort by range
# rows.sort(key = lambda row: int(row['range']))

# plot values
plt.barh(
  np.arange(len(rows)),
  [float(row['speed']) / 1048576 for row in rows], 
  align = 'center',
  alpha = 0.5,
  tick_label = ['{} ({} bytes)'.format(
    row['host'],
    row['size']
  ) for row in rows]
)

# # build title
# algo = os.path.splitext(os.path.basename(sys.argv[1]))[0]
# title = 'OpenSSL Speed Test: {}'.format(algo)

# get title and xlimit
title = sys.argv[3]
limit = int(sys.argv[4])

# # build xlimit
# # if re.match('^aes', algo):
#   limit = 400
# else:
#   limit = 2000

# add label and title
plt.yticks(fontsize = 5)
plt.xlim(0, limit)
# plt.xscale('log')
plt.xlabel('Speed (MB/s)')
plt.title(title, fontsize = 9)
plt.tight_layout()

# save image
plt.savefig(sys.argv[2])
