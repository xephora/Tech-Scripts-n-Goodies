#!/usr/bin/env python

from google.cloud import storage

print(("""\
  ____________                 __   __          
 / ___/ ___/ _ \___ ________ _/ /  / /  ___ ____
/ (_ / /__/ ___/ _ `/ __/ _ `/ _ \/ _ \/ -_) __/
\___/\___/_/   \_, /_/  \_,_/_.__/_.__/\__/_/   
              /___/  Grabs Metadata from Google Storage Buckets
			Created by x3ph
"""))

bucket_name=input('Enter Bucket Name: ')
def list_blobs(bucket_name):

    storage_client = storage.Client()

    blobs = storage_client.list_blobs(bucket_name)

    for blob in blobs:
        print(blob.id + "\n" + blob.storage_class + "\n" + str(blob.metageneration) + "\n" + blob.self_link + "\n" + str(blob.time_created))


if __name__ == "__main__":
     list_blobs(bucket_name)
