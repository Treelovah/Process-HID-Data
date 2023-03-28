import csv

# Map of HID key codes to ASCII characters
hid_to_ascii = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e',
    0x09: 'f', 0x0A: 'g', 0x0B: 'h', 0x0C: 'i', 0x0D: 'j',
    0x0E: 'k', 0x0F: 'l', 0x10: 'm', 0x11: 'n', 0x12: 'o',
    0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
    0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x', 0x1C: 'y',
    0x1D: 'z', 0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4',
    0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9',
    0x27: '0', 0x28: '\n', 0x29: '[ESC]', 0x2a: '[BACKSPACE]',
    0x2C: ' ', 0x2D: '-', 0x2E: '=', 0x2F: '[', 0x30: ']',
    0x32: '#', 0x33: ';', 0x34: "'", 0x36: ',', 0x37: '.',
    0x38: '/', 0x39: '[CAPSLOCK]', 0x2b: '\t', 0x4f: '→',
    0x50: '←', 0x51: '↓', 0x52: '↑', 0x4c: '[NUMLOCK]',
    0x7B: '{', 0x7C: '|', 0x7D: '}', 0x7E: '~', 0x7F: '[DEL]',
}

def read_hid_data():
    with open('hid_data.csv', newline='') as csvfile:
        return [row[6] for row in csv.reader(csvfile) if row[7] == 'URB_INTERRUPT in']

def parse_hid_data(hid_data):
    hex_data = [int(hid_data[i:i+2], 16) for i in range(0, len(hid_data), 2)]

    if hex_data[0] & 0x02:  # AND with 0x02 to check if the 2nd bit is set
        hex_data[0] = 0
    else:
        hid_to_ascii[0x2F] = '['  # Map 0x2F to '['

    return ''.join(hid_to_ascii.get(byte, '') for byte in hex_data[2:])

def main():
    hid_data_list = read_hid_data()
    final_data = ''.join(filter(None, (parse_hid_data(item) for item in hid_data_list)))
    print(f'final data: {final_data}', end='')

main()
