#!/usr/bin/env python3
#
# Usage: ./04-result-intersection.py
#
# This script is supplementary to the key analysis scripts and is used to find
# the intersection of results between two analysis runs. Adjust the file paths
# below to point to the correct result files in CSV format. For a single evaluation
# run, this script is not needed. The output is of the same format as the two inputs.
#

import csv

from config import *

RESULTS_FILE_1 = f"{RESULTS_DIR}/03-analysis-results.csv"
RESULTS_FILE_2 = "<second>/<results>/03-analysis-results.csv"
RESULTS_FILE_OUT = f"{RESULTS_DIR}/04-analysis-results-intersection.csv"

if __name__ == '__main__':
  fpr_set = set()
  with open(RESULTS_FILE_1, 'r') as f:
    reader = csv.reader(f)
    for row in reader:
      fpr_set.add(row[3])
  with open(RESULTS_FILE_2, 'r') as in_file, open(RESULTS_FILE_OUT, 'w') as out_file:
      reader = csv.reader(in_file)
      writer = csv.writer(out_file)
      for row in reader:
        if row[3] in fpr_set:
          writer.writerow(row)
