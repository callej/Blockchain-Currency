package blockchain

import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import kotlin.random.Random

const val HASH_FUNCTION = "SHA-256"
const val POW_LOW_LIMIT_SEC = 3
const val POW_HIGH_LIMIT_SEC = 30
const val MINING_REWARD = 100

fun String.hash(): String {
    val md = MessageDigest.getInstance(HASH_FUNCTION)
    return BigInteger(1, md.digest(toByteArray())).toString(16).padStart(64, '0')
}

data class UserInfo(val userId: String,
                    val name: String,
                    val signed: ByteArray = ByteArray(0),
                    val publicKey: PublicKey = Signature.createKeyPair().public) {

    fun toByteArray() = (this.userId + this.name).toByteArray()
}

data class Transaction(val transId: Int,
                       val from: UserInfo,
                       val to: UserInfo,
                       val amount: Int,
                       val signed: ByteArray = ByteArray(0),
                       val publicKey: PublicKey = Signature.createKeyPair().public) {

    fun toByteArray() = (
            this.transId.toString() +
            this.from.toString() +
            this.to.toString() +
            this.amount.toString()
            ).toByteArray()
}

data class BlockSpec(val blockId: Int,
                     val previousHash: String,
                     val powZeros: Int,
                     val transactions: MutableList<Transaction>)

data class Block(private val blockSpec: BlockSpec,
                 private val magic: Long,
                 private val miningTime: Long,
                 private val miner: UserInfo) {

    val blockId = blockSpec.blockId
    val previousHash = blockSpec.previousHash
    private val powZeros = blockSpec.powZeros
    private val transactions = blockSpec.transactions
    private val timestamp: Long = System.currentTimeMillis()
    private val hash = calculateHash()
    private val maxTransactionId = blockSpec.transactions.maxOfOrNull { it.transId } ?: 0
    private val minTransactionId = blockSpec.transactions.minOfOrNull { it.transId } ?: 0

    fun getCreationTime() = this.miningTime
    fun getPowZeros() = this.powZeros
    fun getStoredHash() = this.hash
    fun getTransactions() = this.transactions
    fun getMaxTransactionId() = this.maxTransactionId
    fun getMinTransactionId() = this.minTransactionId

    fun getUserAssets(user: UserInfo, publicKey: PublicKey): Int {
        if (!Signature.verifyUser(user, publicKey)) {
            throw Exception("Fraud! User can't be verified when asking for assets in block")
        }
        var totalUserBlockAsset = 0
        for (transaction in this.transactions) {
            if (Signature.verifyTransaction(transaction)) {
                if (transaction.to == user) {
                    totalUserBlockAsset += transaction.amount
                }
                if (transaction.from == user) {
                    totalUserBlockAsset -= transaction.amount
                }
            }
        }
        if (user == this.miner) {
            totalUserBlockAsset += MINING_REWARD
        }
        return totalUserBlockAsset
    }

    private fun dataString(): String {
        var dataStr = "Block data:"
        if (this.transactions.isEmpty()) {
            return "$dataStr\nNo transactions"
        } else {
            for (transaction in this.transactions) {
                dataStr += "\n${transaction.from.name} sent ${transaction.amount} VC to ${transaction.to.name}"
            }
            return dataStr
        }
    }

    fun calculateHash(): String {
        return (this.blockId.toString() +
                this.previousHash +
                this.powZeros.toString() +
                this.transactions.toString() +
                this.timestamp.toString() +
                this.magic.toString() +
                this.miningTime.toString() +
                this.miner.toString()
                ).hash()
    }

    fun verifyTransactions(): Boolean {
        for (transaction in this.transactions) {
            if (!Signature.verifyTransaction(transaction)) {
                return false
            }
        }
        return true
    }

    override fun toString(): String {
        return "Block:\n" +
                "Created by: ${this.miner.name}\n" +
                "${this.miner.name} gets $MINING_REWARD VC\n" +
                "Id: ${this.blockId}\n" +
                "Timestamp: ${this.timestamp}\n" +
                "Magic number: ${this.magic}\n" +
                "Hash of the previous block:\n${this.previousHash}\n" +
                "Hash of the block:\n${this.hash}\n" +
                "${dataString()}\n" +
                "Block was generating for ${this.miningTime / 1000} seconds"
    }
}

class BlockChain(private val maxLength: Int) {
    private val blockChain = emptyList<Block>().toMutableList()
    @Volatile private var powZeros = 0
    @Volatile private var doneMining = false
    @Volatile private var miningAvailable = true
    private val transList = emptyList<Transaction>().toMutableList()
    private var blockSpecs = BlockSpec(1, "0", powZeros, ArrayList(this.transList))
    @Volatile private var transactionId = 1
    private val userIdRequests = emptyList<String>().toMutableList()
    private val registeredUsers = emptyMap<String, UserInfo>().toMutableMap()
    private val userIdLock = Any()
    private val registrationLock = Any()
    private val miningLock = Any()
    private val chatLock = Any()
    private val transLock = Any()
    private val idLock = Any()

    fun getUsers() = this.registeredUsers.values

    private fun setupNextBlock() {
        synchronized(this.chatLock) {
            if (this.transList.isEmpty()) {
                this.miningAvailable = false
            } else {
                this.blockSpecs = BlockSpec(
                    this.blockChain.size + 1,
                    this.blockChain.last().getStoredHash(),
                    this.powZeros,
                    ArrayList(this.transList))
                this.transList.clear()
                this.miningAvailable = true
            }
        }
    }

    fun getBlockSpecs() = this.blockSpecs

    fun requestUserId(name: String): String {
        synchronized(this.userIdLock) {
            var userId = (Random.nextLong().toString() + name + System.currentTimeMillis()).hash()
            while (this.registeredUsers.containsKey(userId) || this.userIdRequests.contains(userId)) {
                userId = (Random.nextLong().toString() + name + System.currentTimeMillis()).hash()
            }
            this.userIdRequests.add(userId)
            return userId
        }
    }

    fun registerUser(user: UserInfo): Boolean {
        synchronized(this.registrationLock) {
            if (this.registeredUsers.containsKey(user.userId) ||
                !this.userIdRequests.contains(user.userId) ||
                !Signature.verifyUser(user, user.publicKey)) {
                return false
            } else {
                this.registeredUsers[user.userId] = user
                this.userIdRequests.remove(user.userId)
                return true
            }
        }
    }

    fun requestTransactionId(): Int {
        synchronized(this.idLock) {
            return this.transactionId++
        }
    }

    fun addTransaction(transaction: Transaction): Boolean {
        synchronized(this.transLock) {
            if ((transaction.transId > (this.blockSpecs.transactions.maxOfOrNull { it.transId } ?: 0)) &&
                (Signature.verifyTransaction(transaction)) &&
                (this.registeredUsers.containsValue(transaction.from)) &&
                (this.registeredUsers.containsValue(transaction.from)) &&
                (transaction.amount >= 0) &&
                (this.asset(transaction.from, transaction.publicKey) >= transaction.amount)) {
                this.transList.add(transaction)
                if (!this.miningAvailable) {
                    this.setupNextBlock()
                }
                return true
            } else {
                return false
            }
        }
    }

    fun asset(user: UserInfo, publicKey: PublicKey): Int {
        synchronized(this.transLock) {
            if (!Signature.verifyUser(user, publicKey)) {
                throw Exception("Fraud! User can't be verified when asking for assets")
            }
            var totalAmount = 0
            synchronized(this.miningLock) {
                for (block in this.blockChain) {
                    totalAmount += block.getUserAssets(user, publicKey) +
                            this.assetInTransList(user, publicKey) +
                            this.assetInMiningBlock(user, publicKey)
                }
            }
            return totalAmount
        }
    }

    private fun assetInTransList(user: UserInfo, publicKey: PublicKey): Int {
        synchronized(this.transLock) {
            if (!Signature.verifyUser(user, publicKey)) {
                throw Exception("Fraud! User can't be verified in transList")
            }
            var totalAmount = 0
            for (transaction in this.transList) {
                if (Signature.verifyTransaction(transaction)) {
                    if (transaction.to == user) {
                        totalAmount += transaction.amount
                    }
                    if (transaction.from == user) {
                        totalAmount -= transaction.amount
                    }
                }
            }
            return totalAmount
        }
    }

    private fun assetInMiningBlock(user: UserInfo, publicKey: PublicKey): Int {
        synchronized(this.transLock) {
            if (!Signature.verifyUser(user, publicKey)) {
                throw Exception("Fraud! User can't be verified in MiningBlock")
            }
            if (!this.miningAvailable) {
                return 0
            } else {
                var totalAmount = 0
                for (transaction in this.blockSpecs.transactions) {
                    if (Signature.verifyTransaction(transaction)) {
                        if (transaction.to == user) {
                            totalAmount += transaction.amount
                        }
                        if (transaction.from == user) {
                            totalAmount -= transaction.amount
                        }
                    }
                }
                return totalAmount
            }
        }
    }

    fun addBlock(block: Block) {
        synchronized(this.miningLock) {
            if (this.validNewBlock(block)) {
                this.blockChain.add(block)
                println(block)
                when {
                    (block.getCreationTime() / 1000) < POW_LOW_LIMIT_SEC.toLong() -> {
                        powZeros++
                        println("N was increased to $powZeros\n")
                    }

                    ((block.getCreationTime() / 1000) > POW_HIGH_LIMIT_SEC.toLong()) && (this.powZeros > 0) -> {
                        this.powZeros--
                        println("N was decreased by 1\n")
                    }

                    else -> println("N stays the same\n")
                }
                this.setupNextBlock()
                this.doneMining = this.blockChain.size >= this.maxLength
            }
        }
    }

    private fun validNewBlock(block: Block): Boolean {
        if (this.blockChain.isEmpty()) {
            return ((block.blockId == 1) &&
                    (block.previousHash == "0") &&
                    (block.getStoredHash() == block.calculateHash()) &&
                    (block.getStoredHash().take(this.powZeros) == "0".repeat(this.powZeros)) &&
                    (block.getPowZeros() == this.powZeros) &&
                    (block.getMaxTransactionId() == 0) &&
                    (block.getMinTransactionId() == 0) &&
                    (block.getTransactions().isEmpty()))
        } else {
            return ((block.blockId == (this.blockChain.last().blockId + 1)) &&
                    (block.previousHash == this.blockChain.last().getStoredHash()) &&
                    (block.getStoredHash() == block.calculateHash()) &&
                    (block.getStoredHash().take(this.powZeros) == "0".repeat(this.powZeros)) &&
                    (block.getPowZeros() == this.powZeros) &&
                    (block.verifyTransactions()) &&
                    (block.getMinTransactionId() > this.blockChain.last().getMaxTransactionId()))
//                    (this.validChain()))
        }
    }

    private fun validBlock(block: Block): Boolean {
        if (block.blockId < 1) return false
        if (block.blockId == 1) {
            return ((block.previousHash == "0") &&
                    (block.getStoredHash() == block.calculateHash()) &&
                    (block.getStoredHash().take(block.getPowZeros()) == "0".repeat(block.getPowZeros())) &&
                    (block.getMaxTransactionId() == 0) &&
                    (block.getMinTransactionId() == 0))
        } else {
            return ((block.blockId == (this.blockChain[block.blockId - 2].blockId + 1)) &&
                    (block.previousHash == this.blockChain[block.blockId - 2].getStoredHash()) &&
                    (block.getStoredHash() == block.calculateHash()) &&
                    (block.getStoredHash().take(block.getPowZeros()) == "0".repeat(block.getPowZeros())) &&
                    block.verifyTransactions())
        }
    }

    private fun validChain(): Boolean {
        data class UserCheck(val user: UserInfo, val publicKey: PublicKey)
        if (this.blockChain[0].blockId != 1) return false
        val userSet = emptySet<UserCheck>().toMutableSet()
        for (index in this.blockChain.indices) {
            if (!this.validBlock(this.blockChain[index])) return false
            if ((index > 0) &&
                (this.blockChain[index].getMinTransactionId() <= this.blockChain[index - 1].getMaxTransactionId())) {
                return false
            }
            for (transaction in this.blockChain[index].getTransactions()) {
                userSet.add(UserCheck(transaction.from, transaction.publicKey))
                if ((!this.registeredUsers.containsValue(transaction.from)) ||
                    (!this.registeredUsers.containsValue(transaction.to))) {
                    return false
                }
            }
        }
        for (user in userSet) {
            if ((this.asset(user.user, user.publicKey) < 0) || (user.user.publicKey != user.publicKey)) {
                return false
            }
        }
//        for (user in this.registeredUsers.values) {
//            if (this.asset(user, user.publicKey) < 0) {
//                return false
//            }
//        }
        return true
    }

    fun keepMining() = !this.doneMining

    fun newBlockAvailableForMining() = this.miningAvailable

    override fun toString(): String {
        var str = ""
        for (block in this.blockChain) {
            str += "$block\n"
        }
        return str
    }
}