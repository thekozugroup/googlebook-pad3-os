/* SPDX-License-Identifier: Apache-2.0 */
package org.lineageos.pen

fun main() {
    check(!PenRuntime.canStart(true, true, true, true, true)) // Headless system user 0.
    check(PenRuntime.canStart(true, false, true, true, true)) // Full user 10 on that same device.
    check(PenRuntime.canStart(false, true, true, true, true)) // Native full user 0 must work.
    check(PenRuntime.canStart(false, false, true, true, true))
    check(!PenRuntime.canStart(false, true, true, true, false)) // Private journal requires unlocked user.
    for (connect in listOf(false, true)) for (scan in listOf(false, true)) {
        check(PenRuntime.canStart(false, true, connect, scan, true) == (connect && scan))
    }
    for (action in listOf("BOOT_COMPLETED", "USER_UNLOCKED", "USER_FOREGROUND")) {
        check(PenRuntime.acceptsAction("android.intent.action.$action"))
    }
    for (action in listOf(null, "TEST_START", "android.intent.action.TEST_START", "", "BOOT_COMPLETED")) {
        check(!PenRuntime.acceptsAction(action))
    }

    var refused = 0
    val denied = PenRuntime({ false }) { refused++ }
    check(!denied.start { error("refused startup initialized a resource") })
    check(!denied.available())
    denied.bluetooth { error("refused onStartCommand touched Bluetooth") }
    denied.runIfAllowed { error("refused startup queued work") }
    denied.stop { error("refused onDestroy touched an uninitialized resource") }
    denied.stop { error("duplicate onDestroy initialized resources") }
    check(refused == 1)

    var granted = true
    var initialized = 0
    var cleaned = 0
    refused = 0
    val active = PenRuntime({ granted }) { refused++ }
    check(active.start { initialized++ })
    check(active.start { initialized++ })
    check(initialized == 1 && active.available())
    check(active.bluetooth { 7 } == 7)
    val queued = { active.runIfAllowed { error("queued Bluetooth ran after revocation") } }
    granted = false
    queued()
    check(!active.available() && refused == 1)
    active.stop { cleaned++ }
    active.stop { cleaned++ }
    check(cleaned == 1)
    granted = true
    check(!active.start { error("stopped service restarted without a new lifecycle") })

    granted = true
    refused = 0
    val raced = PenRuntime({ granted }) { refused++ }
    check(raced.start {})
    val result = raced.bluetooth {
        granted = false
        throw SecurityException("test revocation between permission check and Binder call")
    }
    check(result == null && refused == 1 && !raced.available())
    raced.cleanupBluetooth { throw SecurityException("test revoked GATT cleanup") }
    check(refused == 1)
    cleaned = 0
    raced.stop { cleaned++ }
    check(cleaned == 1)

    val unexpected = SecurityException("test non-permission security failure")
    val intact = PenRuntime({ true }) { error("unexpected security error was mislabeled as revocation") }
    check(intact.start {})
    try {
        intact.bluetooth { throw unexpected }
        error("unexpected Bluetooth security failure was swallowed")
    } catch (error: SecurityException) { check(error === unexpected) }
    try {
        intact.cleanupBluetooth { throw unexpected }
        error("unexpected cleanup security failure was swallowed")
    } catch (error: SecurityException) { check(error === unexpected) }
    check(intact.available())
    println("PenRuntimeSelfTest: PASS (headless/full user 0, full user 10, missing grants, lifecycle cleanup, queued revocation, Binder race, unexpected security, protected actions)")
}
