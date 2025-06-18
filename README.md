# Anamorphic Encryption: Private Communication Against a Dictator

This repository contains a conceptual implementation of "Anamorphic Encryption," a cryptographic technique designed to enable private communication even under coercive environments where an adversary (referred to as a "dictator" in the paper) has access to encryption keys and can dictate messages.

## Paper Reference

This implementation is based on the paper:
**"Anamorphic Encryption: Private Communication against a Dictator"**
by Giuseppe Persiano, Duong Hieu Phan, and Moti Yung.
* [https://eprint.iacr.org/2022/639.pdf]

## Implementation Focus

This project demonstrates two core concepts of Anamorphic Encryption:

1.  **Receiver-Anamorphic Encryption:** (Based on the Naor-Yung paradigm)
    * Allows a receiver to obtain a *covert message* ($m_1$) even if they are forced to surrender their "normal" private key, which only reveals an *overt message* ($m_0$) to the coercing adversary.
    * Key properties: Indistinguishability from normal operations, bandwidth rate of 1 (covert bits / overt bits), and zero-latency communication.

2.  **Sender-Anamorphic Encryption:** (Simplified Rejection Sampling)
    * Allows a sender to embed a *covert message* ($m_1$) for an intended recipient, even when forced to send a *specific overt message* ($m_0$) to another party.
    * The simplified implementation uses a "rejection sampling" approach, which is conceptually sound but highly inefficient for multi-bit messages. The paper discusses more advanced, efficient methods like those based on Lattice-LWE.

## Core Concepts demonstrated

* **Overt Message ($m_0$):** The plausible, innocent message visible to the dictator.
* **Covert Message ($m_1$):** The secret message hidden from the dictator.
* **Anamorphic Key Generation:** Creating special key pairs (`aPK`, `aSK`, `dkey`) that enable the hidden channel.
* **Double Key (`dkey`):** The key that allows the intended receiver to decrypt the covert message.
* **Coin-Toss Faking (`fRandom`):** An algorithm used by the sender to generate randomness that allows a single ciphertext to decrypt to different messages depending on the key used.
* **Indistinguishability:** The core security principle that the anamorphic operations should be indistinguishable from normal cryptographic operations to avoid raising suspicion.

## Setup and How to Run

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/Anamorphic-Encryption-Implementation.git](https://github.com/yourusername/Anamorphic-Encryption-Implementation.git)
    cd Anamorphic-Encryption-Implementation
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the demonstration script:**
    ```bash
    python demo_file.py
    ```
    The script will print outputs showing the key generation, encryption, and decryption processes from both the dictator's (overt) and the legitimate receiver's (covert) perspectives.

## Code Structure

* `src/`: Contains the core cryptographic implementations.
    * `base_pke.py`: A simplified ElGamal Public Key Encryption (PKE) scheme, serving as the underlying cryptographic primitive.
    * `nizk_mock.py`: A **MOCK** Non-Interactive Zero-Knowledge (NIZK) proof system.
    * `receiver_am.py`: Implementation of the Receiver-Anamorphic Encryption using the base PKE and NIZK mock.
    * `sender_am.py`: A simplified conceptual implementation of Sender-Anamorphic Encryption using rejection sampling.
    * `utils.py`: Helper functions for cryptographic operations (e.g., modular exponentiation, prime generation, hashing).
* `demo_file.py`: The main script to run and demonstrate the Anamorphic Encryption flows.
* `requirements.txt`: Lists Python package dependencies.
* `README.md`: This file.
* `LICENSE`: The MIT License for the project.

## Important Notes and Limitations

* **NIZK MOCK:** The `nizk_mock.py` module provides a conceptual placeholder for a Non-Interactive Zero-Knowledge proof system. **It is NOT cryptographically secure.** A real, secure NIZK implementation is highly complex and beyond the scope of this demonstration project. Its purpose here is solely to illustrate the *role* of a NIZK in the Naor-Yung transform and its application in Anamorphic Encryption.
* **Simplified Cryptography:** The `base_pke.py` (ElGamal) is simplified for clarity and demonstration. For real-world security, more robust implementations, proper padding, and larger key sizes would be necessary.
* **Sender-AM Efficiency:** The `sender_am.py` implementation uses rejection sampling, which is very inefficient for multi-bit covert messages (as noted in the paper, its runtime can be exponential in message length). More practical Sender-AM schemes rely on advanced techniques like LWE.
* **Message Representation:** Messages are converted to integers for encryption. In a real system, robust encoding and decoding (e.g., using OAEP for ElGamal) would be crucial.
* **Security Parameter (`LAMBDA_BITS`):** The `demo_file.py` uses a small `LAMBDA_BITS` (256) for quick execution. For any real cryptographic application, this value should be much higher (e.g., 1024-2048 bits).

## Author

Fanizza Tahir

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
