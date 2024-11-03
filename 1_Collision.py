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


def find_collision(M, hash_length, max_attempts):
    """
    Find a collision.

    Randomly generates messages of length 1 to 2 characters, calculates their PRSHA-1 hashes and compares them.
    If hashes are the same, a collision has been found. PRSHA-1 hash is a segment of SHA-1 hash that start at {M + 1}
    and ends at {M + 1 + hash_length}.

    :param M: initialization value, aka last two digits of a person's Estonian  ID code.
    :param hash_length: length of PRSHA-1 hash.
    :param max_attempts: max attempts to find a collision.
    :return: All info about the collision: the collision hash, messages that have colliding hashes, attempts taken and
    elapsed time.
    """
    # Start timer
    start_time = time.time()
    hash_message_dict = {}
    attempt_count = 0
    while attempt_count < max_attempts:
        attempt_count += 1
        # Generate a random message with length of 1-3 characters
        message_length = random.randint(1, 2)
        message = ''.join(random.choices(string.ascii_letters + string.digits, k=message_length))
        # Find message hash
        prsha1_hash = prsha_1(message, M + 1, hash_length)
        if prsha1_hash in hash_message_dict and hash_message_dict[prsha1_hash] != message:
            # Found collision
            message1 = message
            message2 = hash_message_dict[prsha1_hash]
            # Calculate the time it took to find the collision
            elapsed_time = time.time() - start_time
            return {
                'hash': prsha1_hash,
                'message1': message1,
                'message2': message2,
                'attempts': attempt_count,
                'time': elapsed_time
            }
        else:
            # No collision, moving to next message
            hash_message_dict[prsha1_hash] = message
    return None  # No collision found within max_attempts


def find_average_attempts(results):
    """
    Find the average number of attempts it took to find a collision.

    :param results: list of found collisions.
    :return: rounded average number of attempts.
    """
    attempts = [result['attempts'] for result in results]
    return round(sum(attempts) / len(attempts))


def find_average_time(results):
    """
    Find the average time it takes to find a collision.

    :param results: list of found collisions.
    :return: rounded average time.
    """
    times = [result['time'] for result in results]
    return round(sum(times) / len(times), 3)


M = 15
hash_length = 20
max_attempts = 10000
results = []
result = find_collision(M, hash_length, max_attempts)
while result:
    results.append(result)
    result = find_collision(M, hash_length, max_attempts)
print(f"Average attempts: {find_average_attempts(results)}")
print(f"Minimum attempts: {min(result['attempts'] for result in results)}")
print(f"Maximum attempts: {max(result['attempts'] for result in results)}")
print(f"Average time: {find_average_time(results)} seconds")
print("----------------------")
if results[0]:
    print(f"It took {results[0]['attempts']} attempts and {results[0]['time']:.3f} seconds to find the first collision")
    print(f"Collision hash (hexadecimal): {results[0]['hash']}")
    print(f"Message 1 (hex): 0x{results[0]['message1'].encode().hex()}")
    print(f"Message 2 (hex): 0x{results[0]['message2'].encode().hex()}")
else:
    print("No collision found within the maximum number of attempts.")
