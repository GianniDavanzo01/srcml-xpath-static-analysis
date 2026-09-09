def hash_to_bucket_index(key: bytearray, num_buckets: int) -> int:
    return hash(key) % num_buckets
