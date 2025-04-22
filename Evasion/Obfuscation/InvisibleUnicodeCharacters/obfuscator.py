######################################################################################################################
# Obfuscator
# 
# This obfuscator first receives the PAYLOAD string and encodes it to 8-bit binary, then convert each byte according to the following rules:
# 
# 0 => \uFFA0
# 1 => \u3164
#
# These special characters look like whitespace characters.
######################################################################################################################


# REPLACE IT WITH YOUR OWN PAYLOAD (JAVASCRIPT) TO EXECUTE
PAYLOAD = """
alert("I am visible now.");
"""


def obfuscate(text: str):
    # Convert each character to binary (8bit)
    binary_string = ''.join(format(ord(c), '08b') for c in text)
    # Convert binary to Hangul Filler (\uFFA0) or Halkwidth Hangul Filler (\u3164)
    encoded = binary_string.replace('0', '\uFFA0').replace('1', '\u3164')
    return encoded


if __name__ == '__main__':
    obfuscated_payload = obfuscate(PAYLOAD)
    print(f'const obfsPayload = {repr(obfuscated_payload)};')
