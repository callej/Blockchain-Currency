package blockchain

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

const val KEYPAIR_ALGORITHM = "RSA"
const val KEY_SIZE = 2048
const val SIGNATURE_ALGORITHM = "SHA256withRSA"

class Signature {

    companion object {
        fun createKeyPair(): KeyPair {
            val kpGen = KeyPairGenerator.getInstance(KEYPAIR_ALGORITHM)
            kpGen.initialize(KEY_SIZE)
            return kpGen.genKeyPair()
        }

        fun signUser(user: UserInfo, privateKey: PrivateKey): ByteArray {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(user.toByteArray())
            return signature.sign()
        }

        fun verifyUser(user: UserInfo, publicKey: PublicKey): Boolean {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initVerify(publicKey)
            signature.update(user.toByteArray())
            return signature.verify(user.signed)
        }

        fun signTransaction(transaction: Transaction, privateKey: PrivateKey): ByteArray {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(transaction.toByteArray())
            return signature.sign()
        }

        fun verifyTransaction(transaction: Transaction): Boolean {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initVerify(transaction.publicKey)
            signature.update(transaction.toByteArray())
            return signature.verify(transaction.signed) &&
                    this.verifyUser(transaction.from, transaction.publicKey) &&
                    this.verifyUser(transaction.to, transaction.to.publicKey)
        }
    }
}