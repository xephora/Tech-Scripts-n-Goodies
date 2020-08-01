import thread
import hashlib
import time

rainbow = {}

def hash_gen(start, end):
    for i in range(start, end):
        rainbow[i] = hashlib.sha1(str(i)).hexdigest()

try:
    startTime = time.time()
    for i in range(0, 100000, 10000):
        thread.start_new_thread(hash_gen, (i, i+10000))

    while True:
        if len(rainbow) == 100000:
            break

    print("Generate 100,000 sha1 hashes in {} seconds".format(time.time() - startTime))

except:
    print("Error: Unable to start thread")
