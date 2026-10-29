/* SPDX-License-Identifier: Apache-2.0 */
package org.lineageos.pen

private class MemoryPeak(raw: String?) : PeakCapStore {
    var peak = PeakValue(raw)
    var journal: PeakState? = PeakState()
    var writable = true
    var readFails = false
    var saveFails = false
    var writeFails = false
    var writeReportsFailureAfterApply = false
    var beforeWrite: (() -> Unit)? = null
    var afterSave: (() -> Unit)? = null
    var writes = 0
    override fun canWrite() = writable
    override fun readPeak() = if (readFails) null else peak
    override fun loadState() = journal
    override fun saveState(state: PeakState): Boolean {
        if (saveFails) return false
        journal = state
        afterSave?.also { afterSave = null }?.invoke()
        return true
    }
    override fun writePeak(expected: PeakValue, value: PeakValue): Boolean {
        beforeWrite?.also { beforeWrite = null }?.invoke()
        if (!writable || peak != expected || writeFails) return false
        check(journal?.previous != null) // The owner's exact desired value must already be durable.
        writes++
        peak = value
        return !writeReportsFailureAfterApply
    }
}

fun main() {
    for (original in listOf("140.0", "144.0", null)) {
        val store = MemoryPeak(original)
        val cap = PeakCap(store)
        cap.update(true)
        check(store.peak.raw == "120.0" && store.journal?.previous == PeakValue(original))
        cap.update(true)
        check(store.writes == 1)
        // A requested Settings value never substitutes for an actual display-rate observation.
        check(!PenProtocol.canAckActivePencil(144f, 120f))
        check(PenProtocol.canAckActivePencil(120f, 120f))
        PeakCap(store).update(false) // Fresh controller recovers the desired value after restart.
        check(store.peak == PeakValue(original) && store.journal == PeakState() && store.writes == 2)
    }
    for (original in listOf("90.0", "60", "120", "120.0", "0", "bad", "NaN", "Infinity")) {
        val store = MemoryPeak(original); val cap = PeakCap(store)
        cap.update(true); cap.stop()
        check(store.peak.raw == original && store.writes == 0 && store.journal == PeakState())
    }
    run {
        val store = MemoryPeak("144"); store.writable = false
        PeakCap(store).update(true)
        check(store.peak.raw == "144" && store.writes == 0 && store.journal == PeakState())
    }
    run {
        val store = MemoryPeak("144"); val cap = PeakCap(store); cap.update(true)
        store.writable = false; cap.update(false); cap.stop()
        check(store.peak.raw == "120.0" && store.journal?.previous?.raw == "144")
        store.writable = true; PeakCap(store).stop()
        check(store.peak.raw == "144" && store.journal == PeakState())
    }
    for (ownerValue in listOf("90", "144", "120", null)) {
        val store = MemoryPeak("144"); val cap = PeakCap(store); cap.update(true)
        store.peak = PeakValue(ownerValue); cap.update(true); cap.stop()
        check(store.peak == PeakValue(ownerValue) && store.writes == 1)
        PeakCap(store).update(true)
        check(store.peak == PeakValue(ownerValue) && store.writes == 1)
        PeakCap(store).update(false)
        check(store.journal == PeakState())
    }
    run {
        val store = MemoryPeak("144"); val cap = PeakCap(store); cap.update(true)
        store.peak = PeakValue("90"); cap.stop() // Owner changed before any observer callback.
        check(store.peak.raw == "90" && store.writes == 1)
    }
    run {
        val store = MemoryPeak("144"); store.beforeWrite = { store.peak = PeakValue("90") }
        PeakCap(store).update(true)
        check(store.peak.raw == "90" && store.writes == 0 && store.journal?.overridden == true)
    }
    run {
        val store = MemoryPeak("144"); val cap = PeakCap(store); cap.update(true)
        store.beforeWrite = { store.peak = PeakValue("90") }; cap.stop()
        check(store.peak.raw == "90" && store.writes == 1)
    }
    run {
        val store = MemoryPeak("144"); store.saveFails = true
        PeakCap(store).update(true)
        check(store.peak.raw == "144" && store.writes == 0)
    }
    run {
        val store = MemoryPeak("144"); store.writeFails = true
        PeakCap(store).update(true)
        check(store.peak.raw == "144" && store.journal == PeakState())
    }
    run {
        val store = MemoryPeak("144"); val cap = PeakCap(store); cap.update(true)
        store.writeFails = true; cap.stop()
        check(store.peak.raw == "120.0" && store.journal?.previous?.raw == "144")
        store.writeFails = false; PeakCap(store).stop()
        check(store.peak.raw == "144")
    }
    run {
        val store = MemoryPeak("144"); store.writeReportsFailureAfterApply = true
        PeakCap(store).update(true)
        check(store.peak.raw == "120.0" && store.journal?.previous?.raw == "144")
        store.writeReportsFailureAfterApply = false; PeakCap(store).stop()
        check(store.peak.raw == "144")
    }
    run {
        val store = MemoryPeak("144"); store.afterSave = { store.writable = false }
        PeakCap(store).update(true)
        check(store.peak.raw == "144" && store.writes == 0)
    }
    run {
        val store = MemoryPeak("144"); store.readFails = true
        PeakCap(store).update(true); check(store.writes == 0)
        store.readFails = false; store.journal = null
        PeakCap(store).update(true); check(store.writes == 0)
    }
    run {
        val store = MemoryPeak("144"); store.journal = PeakState(previous = PeakValue("144"))
        PeakCap(store).update(true) // Interrupted before the original write: preserve the current owner value.
        check(store.peak.raw == "144" && store.writes == 0 && store.journal?.overridden == true)
    }
    println("PeakCapSelfTest: PASS (cap, durable save/restore, unset, 90Hz, restart, denial/revocation, owner overrides, conditional write races, failed reads/writes/journal, actual-rate ACK gate)")
}
