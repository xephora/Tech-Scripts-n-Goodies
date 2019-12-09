#!/usr/bin/env python

#Requires Python3
#Reads and displays TFRecord file
from __future__ import absolute_import, division, print_function, unicode_literals
import tensorflow as tf
import numpy as np
import IPython.display as display

filenames = input('Enter name of tfrecord_file: ')
raw_dataset = tf.data.TFRecordDataset(filenames)

print(raw_dataset)
