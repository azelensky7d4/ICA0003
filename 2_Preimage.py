import hashlib
import random
import string
import time


def get_bits(data, start_bit, hash_length):
    """
    Get only the desired bits from entire 160-bit SHA-1 hash.

    :param data: SHA-1 hash bits.
    :param start_bit: the bit where desired bit segment starts.
    :param hash_length: length of segment.
    :return:
    """
    # Convert bits to string format
    all_bits = ''.join(f"{byte:08b}" for byte in data)
    # Retrieve desired bit segment
    desired_bits = all_bits[start_bit:start_bit + hash_length]
    # Represent the bits in hexadecimal format
    # hex_bits = f"{desired_bits:05X}"
    hex_bits = str(hex(int(desired_bits, 2)))
    return hex_bits


def prsha_1(message, start_bit, hash_length):
    """
    Calculate PRSHA-1 hash.

    :param message: message to hash.
    :param start_bit: start bit for desired segment from SHA-1 hash.
    :param hash_length: desired segment length.
    :return:
    """
    # Calculate sha-1 hash
    sha1_hash = hashlib.sha1(message.encode()).digest()
    # Retrieve desired bits
    prsha1_int = get_bits(sha1_hash, start_bit, hash_length)
    return prsha1_int


def find_preimage(M, P, hash_length, max_attempts):
    # Start timer
    start_time = time.time()
    attempt_count = 0
    p_hash = prsha_1(P, M + 1, hash_length)
    while attempt_count < max_attempts:
        attempt_count += 1
        # Generate a random message with length of 1-11 characters
        message_length = random.randint(1, 5)
        Q = ''.join(random.choices(string.ascii_letters + string.digits, k=message_length))
        # Find message hash
        q_hash = prsha_1(Q, M + 1, hash_length)
        if q_hash == p_hash and P != Q:
            # Found preimage
            # Calculate the time it took to find the preimage
            elapsed_time = time.time() - start_time
            return {
                'hash': q_hash,
                'original': P,
                'preimage': Q,
                'attempts': attempt_count,
                'time': elapsed_time
            }
    return None  # No preimage found within max_attempts


def find_average_attempts(results):
    """
    Find the average number of attempts it took to find a preimage.

    :param results: list of found preimages.
    :return: rounded average number of attempts.
    """
    attempts = [result['attempts'] for result in results]
    return round(sum(attempts) / len(attempts))


def find_average_time(results):
    """
    Find the average time it takes to find a preimage.

    :param results: list of found preimages.
    :return: rounded average time.
    """
    times = [result['time'] for result in results]
    return round(sum(times) / len(times), 3)


M = 15
hash_length = 20
max_attempts = 2000000
P = "50403167015"
results = []
result = find_preimage(M, P, hash_length, max_attempts)
while result:
    results.append(result)
    result = find_preimage(M, P, hash_length, max_attempts)
print(f"Average attempts: {find_average_attempts(results)}")
print(f"Average time: {find_average_time(results)} seconds")
print("----------------------")
if results[0]:
    print(f"It took {results[0]['attempts']} attempts and {results[0]['time']:.3f} seconds to find the first preimage for given P")
    print(f"Preimage hash (hexadecimal): {results[0]['hash']}")
    print(f"Original message P (hex): 0x{results[0]['original'].encode().hex()}")
    print(f"Preimage message Q (hex): 0x{results[0]['preimage'].encode().hex()}")
else:
    print("No preimage found within the maximum number of attempts.")
