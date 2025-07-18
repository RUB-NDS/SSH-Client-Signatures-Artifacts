#!/usr/bin/env python3

import csv

RESULTS_FILE_1 = "results/202306/03-analysis-results.csv"
RESULTS_FILE_2 = "results/202501/03-analysis-results.csv"
RESULTS_FILE_OUT = "results/04-analysis-results-intersection.csv"

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
