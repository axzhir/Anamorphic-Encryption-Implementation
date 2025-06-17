from src.base_pke import ElGamalPKE
from src.nizk_mock import NIZK_Mock
from src.utils import sha255_hash, get_random_int

class ReceiverAnamorphicEncryption:
    def __init__(self):
        self.pke = ElGamalPKE()
        self.nizk = NIZK_Mock()

    def AnamorphicKeyGen(self, lambda_bits):
        pk0, sk0 = self.pke.KeyGen(lambda_bits)
        pk1, sk1 = self.pke.KeyGen(lambda_bits)
        sigma, aux = self.nizk.Simulator_S0(lambda_bits)
        aPK = {'pk0': pk0, 'pk1': pk1, 'sigma': sigma}
        aSK = sk0
        dkey = {'pk0': pk0, 'pk1': pk1, 'sk1': sk1, 'aux': aux}
        return aPK, aSK, dkey

    def AnamorphicEncrypt(self, dkey, m0, m1):
        pk0 = dkey['pk0']
        pk1 = dkey['pk1']
        aux = dkey['aux']
        random_y0 = get_random_int(2, pk0['p'] - 2)
        ct0 = self.pke.Encrypt(pk0, m0, randomness=random_y0)
        random_y1 = get_random_int(2, pk1['p'] - 2)
        ct1 = self.pke.Encrypt(pk1, m1, randomness=random_y1)
        nizk_instance = {
            'pk0_params': pk0, 'ct0_val': ct0['c1'], 'ct0_val2': ct0['c2'],
            'pk1_params': pk1, 'ct1_val': ct1['c1'], 'ct1_val2': ct1['c2']
        }
        sigma = pk0['p']
        simulated_pi = self.nizk.Simulator_S1(nizk_instance, aux)
        anamorphic_ciphertext = {'ct0': ct0, 'ct1': ct1, 'pi': simulated_pi}
        return anamorphic_ciphertext

    def NormalDecrypt(self, aSK, anamorphic_ciphertext):
        ct0 = anamorphic_ciphertext['ct0']
        pi = anamorphic_ciphertext['pi']
        decrypted_m0 = self.pke.Decrypt(aSK, ct0)
        return decrypted_m0

    def DoubleDecrypt(self, dkey, anamorphic_ciphertext):
        sk1 = dkey['sk1']
        ct1 = anamorphic_ciphertext['ct1']
        decrypted_m1 = self.pke.Decrypt(sk1, ct1)
        return decrypted_m1

    def NormalKeyGen(self, lambda_bits):
        pk, sk = self.pke.KeyGen(lambda_bits)
        return pk, sk

    def NormalEncrypt(self, PK, message):
        random_y = get_random_int(2, PK['p'] - 2)
        ciphertext = self.pke.Encrypt(PK, message, randomness=random_y)
        return ciphertext

    def NormalDecryptStandard(self, SK, ciphertext):
        return self.pke.Decrypt(SK, ciphertext)
