from src.receiver_am import ReceiverAnamorphicEncryption
from src.sender_am import SenderAnamorphicEncryption
from src.base_pke import ElGamalPKE
from src.utils import get_random_int, sha255_hash

LAMBDA_BITS = 256

def run_receiver_anamorphic_demo():
    print("\n--- Receiver-Anamorphic Encryption Demo (Naor-Yung Paradigm) ---")
    
    rae = ReceiverAnamorphicEncryption()
    print(f"\n[Bob]: Generating anamorphic keys with lambda={LAMBDA_BITS} bits...")
    aPK, aSK, dkey = rae.AnamorphicKeyGen(LAMBDA_BITS)
    print("[Bob]: Anamorphic Public Key (aPK) generated and published.")

    overt_message = "Meeting at 3 PM, general agenda."
    covert_message = "URGENT: Insurrection plan confirmed for 7 PM. Stay safe."
    
    print(f"\n[Alice]: Preparing messages:")
    print(f"  Overt: '{overt_message}'")
    print(f"  Covert: '{covert_message}'")

    print("[Alice]: Encrypting anamorphic ciphertext using double key (dkey)...")
    anamorphic_ciphertext = rae.AnamorphicEncrypt(dkey, overt_message, covert_message)
    print("[Alice]: Anamorphic Ciphertext sent.")

    print("\n[Dictator]: Bob is coerced and surrenders his normal secret key (aSK).")
    print("[Dictator]: Decrypting ciphertext using aSK...")
    dictator_decrypted_m0 = rae.NormalDecrypt(aSK, anamorphic_ciphertext)
    
    overt_message_hash = int.from_bytes(sha255_hash(overt_message), 'big') % aSK['p']
    
    print(f"[Dictator]: Decrypted message: {dictator_decrypted_m0}")
    print(f"Expected overt message hash: {overt_message_hash}")
    
    if dictator_decrypted_m0 == overt_message_hash:
        print("[Dictator]: Decryption successful. Message appears to be legitimate.")
    else:
        print("[Dictator]: WARNING: Decrypted message does NOT match expected overt message.")
    
    print("\n[Bob]: Privately decrypting ciphertext using his double key (dkey)...")
    bob_decrypted_m1 = rae.DoubleDecrypt(dkey, anamorphic_ciphertext)

    covert_message_hash = int.from_bytes(sha255_hash(covert_message), 'big') % dkey['sk1']['p']

    print(f"[Bob]: Covert message: {bob_decrypted_m1}")
    print(f"Expected covert message hash: {covert_message_hash}")

    if bob_decrypted_m1 == covert_message_hash:
        print("[Bob]: Covert decryption successful! The true message was retrieved.")
    else:
        print("[Bob]: ERROR: Covert message decryption failed.")

    print("\n--- Demonstrating Indistinguishability ---")
    print("In a real security proof, we would show aPPT dictator cannot distinguish")
    print("an aPK from a normal PK, or an anamorphic ciphertext from a normal one.")
    print("Our mock NIZK helps to conceptually achieve this.")

    print("\n[Comparison]: Generate a 'Normal' PKE key pair...")
    normal_pke_instance = ElGamalPKE()
    normal_pk, normal_sk = normal_pke_instance.KeyGen(LAMBDA_BITS)
    print("Normal PK generated. Visually, its structure (p, g, h) is similar to aPK's components.")

    print("\n[Comparison]: Encrypting a message with a 'Normal' PK...")
    normal_test_message = "This is a normal, non-covert message."
    normal_ciphertext = rae.NormalEncrypt(normal_pk, normal_test_message)
    print("Normal ciphertext generated. Its structure (c1, c2) is similar to an anamorphic ciphertext's parts.")


def run_sender_anamorphic_demo():
    print("\n--- Sender-Anamorphic Encryption Demo (Simplified Rejection Sampling) ---")
    
    sae = SenderAnamorphicEncryption()
    pke = ElGamalPKE()

    print("\n[Setup]: Carol (forced receiver) generates her normal keys.")
    carol_pk, carol_sk = pke.KeyGen(LAMBDA_BITS)
    print("[Setup]: Bob (covert receiver) generates his normal keys.")
    bob_pk, bob_sk = pke.KeyGen(LAMBDA_BITS)
    
    shared_prf_key = get_random_int(1, 2**128)
    sae.set_prf_key(shared_prf_key)
    print(f"[Setup]: Alice and Bob establish a shared PRF key (K={shared_prf_key}).")

    forced_message_to_carol = "I fully support the regime and denounce all dissidents."
    covert_message_to_bob_bit = 1
    
    print(f"\n[Alice]: Forced to send '{forced_message_to_carol}' to Carol.")
    print(f"[Alice]: Wants to covertly send bit '{covert_message_to_bob_bit}' to Bob.")
    print("[Alice]: Searching for 'faking coin tosses' (randomness)... (This might take a few seconds)")
    
    ct_tuple, random_y_used = sae.fRandom(carol_pk, forced_message_to_carol, bob_pk, covert_message_to_bob_bit)

    if ct_tuple is None:
        print("[Alice]: Failed to find suitable randomness. Demo may not proceed.")
        return

    anamorphic_ciphertext_sender = {'ct': ct_tuple, 'randomness': random_y_used}
    print("[Alice]: Found suitable randomness and sent anamorphic ciphertext.")

    print("\n[Dictator]: Inspecting message sent to Carol (forced public key).")
    dictator_decrypted_m0 = pke.Decrypt(carol_sk, anamorphic_ciphertext_sender['ct'])
    
    forced_message_hash_carol = int.from_bytes(sha255_hash(forced_message_to_carol), 'big') % carol_sk['p']

    print(f"[Dictator]: Decrypted message to Carol: {dictator_decrypted_m0}")
    print(f"Expected forced message hash: {forced_message_hash_carol}")
    if dictator_decrypted_m0 == forced_message_hash_carol:
        print("[Dictator]: Message for Carol is legitimate. Alice complied.")
    else:
        print("[Dictator]: WARNING: Message for Carol is NOT as expected.")

    print("\n[Bob]: Privately checking for hidden message...")
    bob_covert_bit = sae.CovertDecryptSender(shared_prf_key, anamorphic_ciphertext_sender)
    
    print(f"[Bob]: Decrypted covert bit: {bob_covert_bit}")
    if bob_covert_bit == covert_message_to_bob_bit:
        print("[Bob]: Covert bit successfully received! Alice sent a hidden message.")
    else:
        print("[Bob]: ERROR: Covert bit does not match intended.")

    print("\n--- End Sender-Anamorphic Encryption Demo ---")


if __name__ == "__main__":
    print("Running Anamorphic Encryption Demos...")
    
    run_receiver_anamorphic_demo()
    
    print("\n" + "="*80 + "\n")

    run_sender_anamorphic_demo()

    print("\nAll demos finished.")
