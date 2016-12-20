# Indexes are based on array index [0..] > S-DES Functions [1..]
des_IP = [1,5,2,0,3,7,4,6] # IP
des_IIP = [3,0,2,4,6,1,7,5] # Inverse IP
des_P10 = [2,4,1,6,3,9,0,8,7,5] # P10
des_P8 = [5,2,6,3,7,4,9,8] # P8
des_EP = [3,0,1,2,1,2,3,0] # E/P
des_P4 = [1,3,2,0] # P4

# S-BOX 0
des_s0 =([ 
            [1,0,3,2],
            [3,2,1,0],
            [0,2,1,3],
            [3,1,3,2]
        ])

# S-BOX 1
des_s1 =([
            [0,1,2,3],
            [2,0,1,3],
            [3,0,1,0],
            [2,1,0,3]
        ])

# Gets a binary string from a binary formatted array
def getString(bits):
    # Return converted array bits to string
    return "".join(str(bit) for bit in bits)

# Gets a decimal value from a binary formatted array
def getDecimal(bits):
    # Return converted binary string to a decimal value
    return int(getString(bits), 2)

# Gets a binary formatted array from a decimal value
def getBinary(decimal):
    return [int(n) for n in "{0:02b}".format(decimal)]

# Checks to see if the input is a binary string
def isBinary(string):
    for bit in range(0, len(string)):
        # Test if bits are 0 or 1
        if string[bit] != "0" and string[bit] != "1":
            return False
    return True

# Circular shift the bits used by the LS-1 and LS-2 functions
def circularShift(key, bits):
    # (Bits:End) + (Start:Bits)
    return key[bits:] + key[:bits]

# P10 Function
def calculateP10(key):
    # Make a copy of the key list
    tempKey = key[:]
    for p in range(0, 10):
        # Swap values using P10
        tempKey[p] = key[des_P10[p]]
    return tempKey

# P8 Function
def calculateP8(key):
    # Initialise a new list
    tempKey = []
    for p in range(0, 8):
        # Swap values using P8
        tempKey.insert(p, key[des_P8[p]])
    return tempKey

# P4 Function
def calculateP4(key):
    # Initialise a new list
    tempKey = []
    for p in range(0, 4):
        # Swap values using P4
        tempKey.insert(p, key[des_P4[p]])
    return tempKey

# E/P Function
def calculateEP(key):
    # Initialise a new list
    tempEP = []
    for p in range(0, 8):
        # Insert items into new array using the E/P order
        tempEP.insert(p, key[des_EP[p]])
    return tempEP

# Calculate key using circular shifting and P8 permutation
def calculateKey(key, shift):
    # Calculate the new order of the bits after bit shifting
    newKey = circularShift(key[0:5], shift) + circularShift(key[5:10], shift)
    # Return the calcualted keys - reorder initial key using P8 function
    return calculateP8(newKey), newKey

# Initial Permutation function
def calculateIP(plaintext):
    tempPT = plaintext[:]
    for p in range(0, 8):
        # Reoder the array using the initial permutation order
        tempPT[p] = plaintext[des_IP[p]]
    return tempPT

# Inverse Permutation function
def calculateIIP(key):
    # Make a copy of the key list
    tempIIP = key[:]
    for p in range(0, 8):
        # Reoder the array using the inverse permutation order
        tempIIP[p] = key[des_IIP[p]]
    return tempIIP

# S-BOX Function
def calculateSBOX(key):
    leftBits = key[0:4] # Left bits
    rightBits = key[4:8] # Right bits

    # Get the column and row of S-BOX0
    row = getDecimal([leftBits[0], leftBits[3]])
    column = getDecimal([leftBits[1], leftBits[2]])
    # Get the binary value represented by the integer within S-BOX0
    s0 = getBinary(des_s0[row][column])

    # Get the column and row of S-BOX1
    row = getDecimal([rightBits[0], rightBits[3]])
    column = getDecimal([rightBits[1], rightBits[2]])
    # Get the binary value represented by the integer within S-BOX1
    s1 = getBinary(des_s1[row][column])

    # Return the results of S0 and S1
    return s0, s1

# SW Function
def calculateSwitch(key):
    leftBits = key[0:4] # Left bits
    rightBits = key[4:8] # Right bits
    # Switch left 4 bits to the right hand side
    return rightBits + leftBits

# F function
def calculateF(bits, key):
    # Get reordered bits from EP function
    ep = calculateEP(bits)

    # XOR Results of EP with Key1
    for p in range(0, 8):
        ep[p] ^= key[p]

    # Get calculated values of S-BOX
    s0, s1 = calculateSBOX(ep)

    # Get reordered bits from P4 function
    p4 = calculateP4(s0 + s1)

    # Return the value of P4
    return p4

# FK Function
def calculateFK(ip, key):
    leftBits = ip[0:4] # Left bits
    rightBits = ip[4:8] # Right bits

    # Calculate the F function and return the value of F (P4)
    f = calculateF(rightBits, key)

    # XOR left bits on the returned P4 bits (F function)
    for p in range(0, 4):
        leftBits[p] ^= f[p]

    # Combine the left bits with the right bits
    return leftBits + rightBits

# Encrypt using S-DES
def encrypt(key, plaintext):
    # Calculate Key1 from P10 and P8 permutation and the circular left shift key
    key1, lsKey1 = calculateKey(calculateP10(key), 1)
    # Calculate Key2 from P8 permutation and the circular left shift key
    key2, lsKey2 = calculateKey(lsKey1, 2)
    # Calculate the initial permutation
    ip = calculateIP(plaintext)
    # Calculate FK1 using the FK > F function
    fk1 = calculateFK(ip, key1)
    # Switch the bits
    sw = calculateSwitch(fk1)
    # Calculate FK2 using the FK > F function
    fk2 = calculateFK(sw, key2)
    # Calculate the inverse permutation
    iip = calculateIIP(fk2)
    # Return the value of the inverse permutation
    return iip

# Decrypt using S-DES
def decrypt(key, ciphertext):
    # Calculate Key1 from P10 permutation and the circular left shift key
    key1, lsKey1 = calculateKey(calculateP10(key), 1)
    # Calculate Key2 and the circular left shift key
    key2, lsKey2 = calculateKey(lsKey1, 2)
    # Calculate the initial permutation
    ip = calculateIP(ciphertext)
    # Calculate FK2 using the FK > F function
    fk2 = calculateFK(ip, key2)
    # Switch the bits
    sw = calculateSwitch(fk2)
    # Calculate FK1 using the FK > F function
    fk1 = calculateFK(sw, key1)
    # Calculate the inverse permutation
    iip = calculateIIP(fk1)
    # Return the value of the inverse permutation
    return iip

# Get the users input and validate to ensure all the algorithm conditions are met
def getUserInput(mode):
    key = text = 0

    while True:
        # Get the 10bit key from the users keybaord and validate
        key = raw_input("\nPlease enter an 10bit key: ")

        # Validate the input length
        if len(key) != 10:
            print key, "must be 10bits. Please try again."
        else:
            if isBinary(key):
                # Convert the input key into a binary array format
                key = [int(bit) for bit in key]
                break
            else:
                print key, "is not in a valid binary format. Please try again."

    while True:
        # Get the 8bit plaintext/ciphertext from the users keybaord and validate
        if mode == 1:
            text = raw_input("\nPlease enter an 8bit plaintext: ")
        else:
            text = raw_input("\nPlease enter an 8bit ciphertext: ")

        # Validate the input length
        if len(text) != 8:
            print text, "must be 8bits. Please try again."
        else:
            if isBinary(text):
                # Convert the input plaintext/ciphertext into a binary array format
                text = [int(bit) for bit in text]
                break
            else:
                print text, "is not in a valid binary format. Please try again."

    # Return the input values
    return key, text

# Driver
while True:
    try:
        # Get the USERS selection from the users keyboard
        input_mode = int(raw_input(">> Enter '1' for Encryption\n>> Enter '2' for Decryption\n>> Enter '3' to Exit\n\nPlease enter your choice: "))
    
        # Check to see if we are encrypting/decrypting based on the user selection
        if input_mode == 1 or input_mode == 2:
            key, text = getUserInput(input_mode)
        
        if input_mode == 1 :
            # Execute the S-DES Encrpytion
            print "\nCiphertext =", getString(encrypt(key, text)), "\n"
        elif input_mode == 2:
            # Execute the S-DES Decryption
            print "\nPlaintext =", getString(decrypt(key, text)), "\n"
        elif input_mode == 3:
            # Exit the application
            break
        else:
            print "\n--- Selected choice is invalid. Please try again.\n"
    except ValueError: # Validate user input
        print "\n--- Selected choice is invalid. Please try again.\n"