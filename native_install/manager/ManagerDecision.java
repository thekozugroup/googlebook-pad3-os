final class ManagerDecision {
    static final int READY = 0, INSTALL = 10, REFUSE = 20;
    static int decide(boolean present, boolean officialCertificate, long version,
                      boolean dataPath, boolean systemPath, boolean canonicalRegularFile) {
        if (!present) return INSTALL;
        if (!officialCertificate || !canonicalRegularFile || (!dataPath && !systemPath)) return REFUSE;
        if (dataPath && version >= 41100) return READY;
        if (version > 41100) return REFUSE; // Never downgrade a newer system package either.
        return INSTALL;
    }
}
