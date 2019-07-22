#!/usr/bin/python3

#
# Generate chart from JSON using matplotlib.
#
# (See PiBench::Runner#save_svg in run.rb for JSON details).
#

import json
import sys
import os
import numpy as np
import matplotlib.pyplot as plt

# check arguments
if len(sys.argv) < 2:
  print("Usage: {} json_data".format(sys.argv[0]))
  exit(-1)

# decode json data from first argument
data = json.loads(sys.argv[1])

# plot values
plt.barh(
  np.arange(len(data['rows'])),
  [row[1] for row in data['rows']],
  align = 'center',
  alpha = 0.5,
  tick_label = [row[0] for row in data['rows']]
)

# set plot parameters
plt.yticks(fontsize = data['fontsize']['yticks'])
plt.xlim(0, data['xlimit'])
plt.xlabel(data['xlabel'])
plt.title(data['title'], fontsize = data['fontsize']['title'])
plt.tight_layout()

# set output size
fig = plt.gcf()
fig.set_size_inches(data['size'][0], data['size'][1])

# save plot
plt.savefig(data['path'], dpi = data['dpi'])
