import numpy as np


CURVES_AND_MSGS_PATH = "./EMSE/etudiant - 2/"
RESULTED_PRIVATE_KEY_PATH = "./D.txt"


class CPA():

    """
    Class for a number of methods and helper functions to compute, print and save the 
    private key from message and the traces of their power consumption
    :param path: path for messages and traces
    """

    n = 1
    messages = []
    traces = []
    path = "./"
    currentlyCalculatedPrivateKeyAsAList = []
    currentlyCalculatedPrivateKeyAsABinary = ""
    currentlyCalculatedPrivateKeyAsAnInt = 0

    def __init__(self, path):
        self.path = path
        self.readModulus()
        self.readMessages(999)
        self.readTraces(999)

    def readModulus(self):
        """
        Read the modulus from N.txt file
        :return: modulus
        """
        file = open(self.path+"N.txt", 'r')
        self.n = int(file.read())
        return self.n

    def readMessages(self, numberOfMessages):
        """
        Read the messages from msg_i files and put them into a list of messages
        :param numberOfMessages: number of messages
        :return: list of messages
        """
        self.messages = []
        for messageIterator in range(numberOfMessages):
            file = open(self.path + "msg_" +
                        str(messageIterator) + ".txt", "r")
            for line in file:
                self.messages.append(int(line.split()[0]))
            file.close()
        return self.messages

    def readTraces(self, numberOfTraces):
        """
        Read the traces from curve_i files and put them into a list of traces
        :param numberOfTraces: number of traces
        :return: list of traces
        """
        self.traces = []
        for traceIterator in range(numberOfTraces):
            file = open(self.path + "curve_" +
                        str(traceIterator) + ".txt", "r")
            for line in file:
                self.traces.append([float(x) for x in line.split()])
            file.close()
        return self.traces

    def computehammingWeight(self, x):
        """
        Compute the Hamming Weight of a number
        :param x: number
        :return: the Hamming Weight of x
        """
        return bin(x).count("1")

    def M_d_mod_N(self, M, d, N):
        """
        Compute the result of RSA exponentiation of a M power d module N
        :param M: message
        :param d: private key
        :param N: modulus
        :return: result of the RSA exponentiation
        """
        T = M
        for i in range(len(d) - 2, -1, -1):
            T = (T**2) % N
            if (d[i] == 1):
                T = (T*M) % N
            else:
                if i == 0:
                    # The end
                    T = (T**2) % N
        return T

    def computePrivateKey(self):
        """
        Compute the private key from crypted messages and their traces
        :param n: modulus
        :param traces: traces of power consumption for crypting messages
        :param messages: crypted messages
        :return: private key
        """
        n = self.n
        traces = self.traces
        messages = self.messages
        estimatedBitsOfKey = [1]
        hammingWeightsOfZeros = [0 for i in range(999)]
        hammingWeightsOfOnes = [0 for i in range(999)]
        tracesIterator = 1
        while tracesIterator < len(traces[0]):
            if (traces[0][tracesIterator] == -1000):
                break

            corrForZero = self.computeCorrOfTracesAndHammingWeight(
                traces, messages, tracesIterator, estimatedBitsOfKey, hammingWeightsOfZeros, 0, n)
            corrForOne = self.computeCorrOfTracesAndHammingWeight(
                traces, messages, tracesIterator, estimatedBitsOfKey, hammingWeightsOfOnes, 1, n)

            if (corrForOne <= corrForZero):
                estimatedBitsOfKey = [0] + estimatedBitsOfKey
                tracesIterator += 1
            else:
                estimatedBitsOfKey = [1] + estimatedBitsOfKey
                tracesIterator += 2

        estimatedBitsOfKey.reverse()
        self.currentlyCalculatedPrivateKeyAsAList = estimatedBitsOfKey
        self.currentlyCalculatedPrivateKeyAsABinary = "".join(
            [str(bit) for bit in self.currentlyCalculatedPrivateKeyAsAList])
        self.currentlyCalculatedPrivateKeyAsAnInt = int(
            self.currentlyCalculatedPrivateKeyAsABinary, 2)
        return self.currentlyCalculatedPrivateKeyAsABinary

    def computeCorrOfTracesAndHammingWeight(self, traces, messages, tracesIterator, estimatedBitsOfKey, hammingWeightsOfTargetBit, targetBit, n):
        """
        Compute the correlation between the Traces from the curves data and Hamming Weights of modular exponentiation of
        the message and hypothesis of the key for Either 0 or 1.
        :param n: modulus 
        :param traces: traces of power consumption for crypting messages
        :param messages: crypted messages 
        :param tracesIterator: current trace index
        :param estimatedBitsOfKey: previously estimated bits from the private key
        :param hammingWeightsOfTargetBit: previously calculated Hamming Weights for 0 or 1
        :param targetBit: 0 or 1
        :return: correlation between the Traces and Hamming Weights
        """
        for messageIterator in range(len(messages)):
            temporaryBitsOfKey = [targetBit] + estimatedBitsOfKey
            hammingWeightsOfTargetBit[messageIterator] = self.computehammingWeight(
                self.M_d_mod_N(messages[messageIterator], temporaryBitsOfKey, n))

        corrOfTracesAndHW = np.corrcoef(
            hammingWeightsOfTargetBit, [trace[tracesIterator:tracesIterator + 1] for trace in traces], False)

        return corrOfTracesAndHW[1][0]

    def printPrivateKey(self):
        """
        Print the Private Key resulted by the compute method as a Binary
        """
        print(self.currentlyCalculatedPrivateKeyAsABinary)

    def savePrivateKeyToFile(self, privateKeyPath):
        """
        Save the Private Key resulted by the compute method as a Binary to a file
        :param privateKeyPath: path where to save the Private Key 
        """
        file = open(privateKeyPath, 'w+')
        file.write(self.currentlyCalculatedPrivateKeyAsABinary)
        file.close()


cpaForRSA = CPA(CURVES_AND_MSGS_PATH)
cpaForRSA.computePrivateKey()
cpaForRSA.printPrivateKey()
cpaForRSA.savePrivateKeyToFile(RESULTED_PRIVATE_KEY_PATH)
