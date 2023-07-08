package blockchain

import java.security.PrivateKey
import java.security.PublicKey
import kotlin.random.Random

class Miner(private val name: String, private val blockChain: BlockChain) : Thread() {
    private val privateKey: PrivateKey
    private val publicKey: PublicKey
    private val me: UserInfo

    init {
        val keyPair = Signature.createKeyPair()
        this.privateKey = keyPair.private
        this.publicKey = keyPair.public
        var myId = blockChain.requestUserId(this.name)
        var mySignature = Signature.signUser(UserInfo(myId, this.name), this.privateKey)
        var myUser = UserInfo(myId, this.name, mySignature, this.publicKey)
        while (!blockChain.registerUser(myUser)) {
            myId = blockChain.requestUserId(this.name)
            mySignature = Signature.signUser(UserInfo(myId, this.name), this.privateKey)
            myUser = UserInfo(myId, this.name, mySignature, this.publicKey)
        }
        this.me = myUser
    }

    override fun run() {
        val person = User(this.me, this.blockChain, this.privateKey)
        person.start()
        nextSpec@ while (this.blockChain.keepMining()) {
            if (this.blockChain.newBlockAvailableForMining()) {
                val timestamp: Long = System.currentTimeMillis()
                val blockSpecs = this.blockChain.getBlockSpecs()
                var newBlock = Block(
                    blockSpecs,
                    Random.nextLong(),
                    System.currentTimeMillis() - timestamp,
                    this.me)
                while (newBlock.calculateHash().take(blockSpecs.powZeros) != "0".repeat(blockSpecs.powZeros)) {
                    newBlock = Block(
                        blockSpecs,
                        Random.nextLong(),
                        System.currentTimeMillis() - timestamp,
                        this.me)
                    if (blockSpecs != this.blockChain.getBlockSpecs() || !this.blockChain.keepMining()) {
                        continue@nextSpec
                    }
                }
                this.blockChain.addBlock(newBlock)
            }
        }
        person.join(1)
    }
}