from random import randint, choice, seed
import sys

MAX_ID = 10000
MAX_INCOME = 1000
CLIENTS_COUNT = 100


def randNotKey(m):
    x = randint(1, MAX_ID)
    while m.has_key(x):
        x = randint(1, MAX_ID)
    
    return x

def main():

    seed()

    aliceData = {}
    bobData = {}


    for _ in range(CLIENTS_COUNT):
        x = randNotKey(aliceData)
        y = randint(1, MAX_INCOME)
        aliceData[x] = y

        x = randNotKey(bobData)
        y = randint(1, MAX_INCOME)
        bobData[x] = y

    keysA = set(aliceData.keys())
    keysB = set(bobData.keys())
    intersection = keysA & keysB

    sumA = 0
    sumB = 0
    avgA = 0
    avgB = 0

    for id in intersection:
        sumA += aliceData[id]
        sumB += bobData[id]
        
    if (len(intersection) > 0):
        avgA = sumA / len(intersection)
        avgB = sumB / len(intersection)

    expected_out_file = open("expected_out", "w")
    expected_out_file.write('Alice average is: ' + str(avgA) + '\n')
    expected_out_file.write('Bob average is: ' + str(avgB) + '\n')


    aliceFile = open("alice_data", "w")
    bobFile = open("bob_data", "w")

    for key in aliceData:
        aliceFile.write(str(key) + '\t' + str(aliceData[key]) + '\n')

    for key in bobData:
        bobFile.write(str(key) + '\t' + str(bobData[key]) + '\n')


if __name__ == '__main__':
    main()
