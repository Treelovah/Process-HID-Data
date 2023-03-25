"""
This is for the Logger challenge on Hack The Box.
The challenge is to download the pcap file and find the flag -- the flag was in the HID packets.
To do this, we must find the HID packets, and then decode them.

First, we should filter the packets to only show the HID packets.
We can definitely do this in wireshark with the following filter: 
    usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)
Let's break down this filter.
The `usb.transfer_type == 0x01` is a common expression used in Wireshark to capture USB bulk transfer packets.
In USB, there are several types of data transfers that can be made between a USB host (such as a computer) and a USB device (such as a keyboard). 
The different types of transfers have different properties and are used for different purposes.
Bulk transfers are one of the types of transfers in USB. They are used for non-time-critical data transfers that can tolerate some delay in delivery. 
Examples of data that might be transferred using bulk transfers include keyboard keystrokes, where the timing of the individual keystrokes is not critical to the overall performance of the system.

In Wireshark, you can apply a filter to capture only the packets of a specific type. 
In this case, usb.transfer_type == 0x01 filters the captured packets to only include USB bulk transfers.

Next, adding `and frame.len == 35` to the filter narrows down the captured packets even further, by selecting only those packets that have a length of 35 bytes.

In a USB keyboard, each keystroke is typically sent as a packet that is 8 bytes long. 
The first byte of the packet is a modifier byte that indicates which modifier keys (e.g., SHIFT, CTRL) are currently pressed, and the second byte is typically set to zero. 
The remaining 6 bytes represent the scan code of the key that was pressed.

By default, Wireshark captures all packets on the selected interface, which includes packets that may not be related to keyboard input. 
Some of these packets may have a different length than the typical keyboard packet length of 8 bytes.
By adding frame.len == 35 to the filter, you're selecting only packets that have a length of 35 bytes, which suggests that they are keyboard packets containing 4 keystrokes (i.e., 4 x 8 bytes + 3 bytes of overhead).

So, in summary, adding `and frame.len == 35` to the filter helps to narrow down the captured packets to only those that are likely to contain keyboard input, which can make it easier to analyze the data.

Finally, adding `and !(usb.capdata == 00:00:00:00:00:00:00:00)` to the filter is used to exclude packets where the payload (capdata) is all zeros.
In a USB keyboard, when a key is released, a corresponding packet is sent with a payload (capdata) of all zeros. 
These packets do not contain any useful information about the key that was released, so they can be excluded from the capture to reduce the amount of data that needs to be analyzed.

By adding `and !(usb.capdata == 00:00:00:00:00:00:00:00)` to the filter, you're selecting only packets where the payload is not all zeros, which are more likely to contain useful information about keyboard input.

Now that the filter is set, we start seeing HID Data packets. This is exaclty what we want.
But... what are HID Data packets?

HID (Human Interface Device) data packets are used to transfer data between a USB host and a USB device that implements the HID protocol, such as a keyboard, mouse, joystick, or gamepad. 
The HID protocol defines a standard way for devices to communicate their inputs and outputs to the host, without requiring the host to know the specific details of each device's protocol.
In the context of USB keyboards, HID data packets are used to transfer information about keyboard inputs, such as which key was pressed or released. 
Each HID data packet contains a payload that represents the state of the keyboard's modifier keys (e.g., SHIFT, CTRL), as well as up to six key codes that represent the keys that are currently pressed.

As we became aware of before, HID data packets are typically sent using the USB interrupt transfer mechanism, which allows for low-latency and low-jitter transfers of time-critical data. 
When a key is pressed or released on a USB keyboard, a HID data packet is sent to the host to indicate the new state of the keyboard. 
The host can then interpret the HID data packet to determine which key was pressed or released, and take the appropriate action (e.g., display the corresponding character on the screen).

By capturing HID data packets using Wireshark, we can analyze the contents of the packets and gain a deeper understanding of how the keyboard is communicating with the host.

Perfect! so knowing this, we have isolated the HID packets, and now we can decode them.
But, how do we decode them?

Frist, we will export the captured HID data packets to a CSV file in Wireshark and then use a Python program to map the data to ASCII.
    Start Wireshark and open the capture file that contains the HID data packets.
    Select "File > Export Packet Dissections > As CSV" from the menu bar.
    In the "Export As CSV" dialog, select the "Selected" option and choose the HID data packets that you want to export. You can use the "Apply a Display Filter" option to filter the packets before exporting them.
    Choose a filename and location for the exported CSV file, and click "Save".
Once we have exported the HID data packets to a CSV file, we can use a Python program to read the file and map the data to ASCII. 


————CODE————— 
This code reads HID (Human Interface Device) data from a CSV file, interprets it, and prints the corresponding ASCII characters. Let's break down the code step by step:
    1. Import the csv module to read data from a CSV file.
    2. Create a dictionary called hid_to_ascii that maps HID key codes to their corresponding ASCII characters.
    3. Define a function read_hid_data that reads data from the hid_data.csv file and returns a list of HID data payloads (row[6]) for rows where the URB type is 'URB_INTERRUPT in' (row[7]).
    4. Define a function parse_hid_data that takes an HID data payload as input and processes it as follows:
        a. Convert the hex string into a list of integer values (hex_data).
        b. Check if the left shift bit is set to 1 (if the first byte hex_data[0] has the 0x02 bit set). If so, map the 0x2F key code to '{' and set the first byte of hex_data to 0. Otherwise, map the 0x2F key code to '['.
        c. Skip the first two bytes of hex_data (the modifier byte and padding byte) and convert the remaining bytes to their corresponding ASCII characters using the hid_to_ascii dictionary. Return the joined ASCII characters as a string.
    5. Define the main function that performs the following steps:
        a. Call the read_hid_data function to get a list of HID data payloads (hid_data_list).
        b. For each item in hid_data_list, call the parse_hid_data function and filter out any None values (if any). Then, join the parsed ASCII strings to form the final_data string.
        c. Print the final_data string.

    6. Finally, call the main() function to execute the code. The program will read the HID data from the CSV file, parse it, and print the final ASCII representation of the data.
    
    This code isn't perfect, but it's a good starting point for analyzing the HID data.
    
    To make the final adjustments, if we wanted to make it more readable,
    we could take the up arrow which is mapped to 0x52, and map it to 0x39 which is caps lock.
    Next, we could map 0x2D to an underscore instead of a hyphen.
    Doing these 2 things would really make a load of difference in readability.
"""


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
