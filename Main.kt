package blockchain

const val BLOCKCHAIN_MAX_LENGTH = 15
const val MINERS = 10
const val USER_NAMES = "John Anne Bert Princess Steve Sugar Billy Tina Eric Betty Stan Jodi Sean Virginia Adam Cindy Elliott Lena Boris Diana Prince Goldie"
const val USERS = 10

fun main() {
    val crypto = BlockChain(BLOCKCHAIN_MAX_LENGTH)
    val miners = emptyList<Miner>().toMutableList()
    repeat(MINERS) { miners.add(Miner("miner${it + 1}", crypto).apply { this.start() }) }
    val users = emptyList<User>().toMutableList()
    val userList = USER_NAMES.split(" ").shuffled().take(USERS)
    repeat(USERS) { users.add(User(UserInfo("", userList[it]), crypto).apply { this.start() }) }
    miners.forEach { it.join() }
    users.forEach { it.join(1) }
}