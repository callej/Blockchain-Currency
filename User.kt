package blockchain

import java.security.PrivateKey
import java.security.PublicKey

class User(private val user: UserInfo,
           private val blockChain: BlockChain,
           private val pk: PrivateKey = Signature.createKeyPair().private) : Thread() {

    private val privateKey: PrivateKey
    private val publicKey: PublicKey
    private val me: UserInfo

    init {
        if (user.userId.isEmpty()) {
            val keyPair = Signature.createKeyPair()
            this.privateKey = keyPair.private
            this.publicKey = keyPair.public
            var myId = blockChain.requestUserId(this.user.name)
            var mySignature = Signature.signUser(UserInfo(myId, this.user.name), this.privateKey)
            var myUser = UserInfo(myId, this.user.name, mySignature, this.publicKey)
            while (!blockChain.registerUser(myUser)) {
                myId = blockChain.requestUserId(this.user.name)
                mySignature = Signature.signUser(UserInfo(myId, this.user.name), this.privateKey)
                myUser = UserInfo(myId, this.user.name, mySignature, this.publicKey)
            }
            this.me = myUser
        } else {
            this.privateKey = this.pk
            this.publicKey = this.user.publicKey
            this.me = this.user
        }
    }

    override fun run() {
        while (blockChain.keepMining()) {
            sleep((1..10000).random().toLong())
            val myAsset = blockChain.asset(this.me, this.publicKey)
            if (myAsset > 0) {
                val amount = (1..myAsset).random()
                val recipient = this.blockChain.getUsers().random()
                var transactionId = this.blockChain.requestTransactionId()
                var mySignature = Signature.signTransaction(Transaction(transactionId, this.me, recipient, amount), this.privateKey)
                var transaction = Transaction(transactionId, me, recipient, amount, mySignature, this.publicKey)
                while (!this.blockChain.addTransaction(transaction)) {
                    transactionId = this.blockChain.requestTransactionId()
                    mySignature = Signature.signTransaction(Transaction(transactionId, this.me, recipient, amount), this.privateKey)
                    transaction = Transaction(transactionId, me, recipient, amount, mySignature, this.publicKey)
                }
            }
        }
    }
}