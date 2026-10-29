// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pen

fun main() {
    check(PenProtocol.pencilAddress("0xf86fde123456_(Time:103ms)") == "F8:6F:DE:12:34:56")
    check(PenProtocol.pencilAddress(" f86fde123456\n") == "F8:6F:DE:12:34:56")
    check(PenProtocol.pencilAddress("F86FDE123456") == "F8:6F:DE:12:34:56")
    check(PenProtocol.pencilAddress("0xabc12345_(Time:0ms)") == "00:00:AB:C1:23:45")
    check(PenProtocol.pencilAddress("abc12345") == "00:00:AB:C1:23:45")
    for (address in listOf(null, "", "0x000000000000_(Time:0ms)", "ffffffffffff",
            "0xf86fde123456_(Time:badms)", "0xf86fde1234567_(Time:1ms)",
            "0xf86fde123456;command", "123456789abc00", "not-an-address")) {
        check(PenProtocol.pencilAddress(address) == null)
    }
    check(!PenProtocol.canAckActivePencil(144f, 120f))
    check(PenProtocol.canAckActivePencil(120f, 120f))
    check(PenProtocol.canAckActivePencil(120.00001f, 120f))
    check(PenProtocol.canAckActivePencil(60f, 120f))
    check(!PenProtocol.canAckActivePencil(120.51f, 120f))
    check(!PenProtocol.canAckActivePencil(144f, 144f))
    for (invalid in listOf(Float.NaN, Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, 0f, -1f)) {
        check(!PenProtocol.canAckActivePencil(invalid, 120f))
        check(!PenProtocol.canAckActivePencil(120f, invalid))
    }
    for (length in 0..4) check(PenProtocol.parsePencilStatus(ByteArray(length)) == null)
    check(PenProtocol.parsePencilStatus(byteArrayOf(0x2c, 0x90.toByte(), 1, 1, 1)) == true)
    check(PenProtocol.parsePencilStatus(byteArrayOf(0x2c, 0x90.toByte(), 1, 1, 0)) == false)
    check(PenProtocol.parsePencilStatus(byteArrayOf(0x2c, 0x90.toByte(), 1, 1, 2)) == null)
    for (invalid in listOf("", "00", "0000", "000000", "00gg0203", "0001020", "00zzzzzz")) {
        check(PenProtocol.decodeCommand(invalid) == null)
    }
    val speed = PenProtocol.decodeCommand("00020300") ?: error("valid command rejected")
    check(speed.contentEquals(byteArrayOf(0xaa.toByte(), 2, 3, 0)))
    check(PenProtocol.isSpeedCommand(speed))
    check(PenProtocol.pencilStatusAck(true).contentEquals(byteArrayOf(0x2c, 0x90.toByte(), 1, 1, 1)))
    println("ProtocolSelfTest: PASS (driver addresses, rate gate, nonfinite bounds, status lengths, malformed commands, ACK bytes)")
}
