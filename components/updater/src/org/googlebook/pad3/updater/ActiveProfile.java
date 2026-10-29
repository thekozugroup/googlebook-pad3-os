package org.googlebook.pad3.updater;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.UserHandle;
import android.system.*;
import java.io.File;
import java.nio.file.Files;

/** Resolve the current UI user's installed package through the donor framework. */
final class ActiveProfile {
    static final String PACKAGE = "org.googlebook.pad3.updater";
    final int packageUser, uid, requestedUid;
    final File data, files;

    private ActiveProfile(int packageUser, int uid, int requestedUid, File data, File files) {
        this.packageUser=packageUser; this.uid=uid; this.requestedUid=requestedUid; this.data=data; this.files=files;
    }
    static int currentUser() throws Exception {
        return (Integer)Class.forName("android.app.ActivityManager").getMethod("getCurrentUser").invoke(null);
    }
    static void ownedDirectory(File path, int uid) throws Exception {
        StructStat stat = Os.lstat(path.getPath());
        UpdateCore.require(OsConstants.S_ISDIR(stat.st_mode) && !Files.isSymbolicLink(path.toPath()), "Private directory ownership/type mismatch");
        UpdateCore.guardPrivateDirectory(stat.st_uid, stat.st_gid, stat.st_mode, uid);
    }
    static ActiveProfile resolve(int requestedUid, boolean needFiles) throws Exception {
        int active = currentUser();
        UpdateCore.require(active >= 0, "No active Android user");
        Class<?> threadClass = Class.forName("android.app.ActivityThread");
        Object thread = threadClass.getMethod("systemMain").invoke(null);
        Context system = (Context)threadClass.getMethod("getSystemContext").invoke(thread);
        UserHandle user = (UserHandle)UserHandle.class.getMethod("of", int.class).invoke(null, active);
        Context application = (Context)Context.class.getMethod("createPackageContextAsUser", String.class, int.class, UserHandle.class)
                .invoke(system, PACKAGE, 0, user);
        ApplicationInfo info = application.getApplicationInfo();
        int packageUser = (Integer)UserHandle.class.getMethod("getUserId", int.class).invoke(null, info.uid);
        UpdateCore.guardUser(active, packageUser, info.uid, requestedUid);
        UpdateCore.require(PACKAGE.equals(application.getPackageName()) && new File(info.sourceDir).getCanonicalFile().equals(new File(RootInstaller.APK).getCanonicalFile()),
                "Active user's updater package is not the built-in APK");
        File rawData = application.getDataDir().getAbsoluteFile();
        UpdateCore.require(rawData.getName().equals(PACKAGE), "Unexpected framework package directory");
        // Resolve only the OS-owned parent alias (user 0 may map to /data/data).
        File parent = rawData.getParentFile().getCanonicalFile();
        StructStat parentStat = Os.lstat(parent.getPath());
        UpdateCore.require(OsConstants.S_ISDIR(parentStat.st_mode) && (parentStat.st_uid == 0 || parentStat.st_uid == 1000)
                && (parentStat.st_mode & 0002) == 0 && ((parentStat.st_mode & 0020) == 0 || parentStat.st_gid == 0 || parentStat.st_gid == 1000),
                "Untrusted framework data parent");
        File data = new File(parent, rawData.getName());
        ownedDirectory(data, info.uid);
        File files = null;
        if (needFiles) {
            // Check existence/ownership before getFilesDir so root never creates an app-owned directory.
            ownedDirectory(new File(data, "files"), info.uid);
            File rawFiles = application.getFilesDir().getAbsoluteFile();
            UpdateCore.require(rawFiles.getParentFile().getCanonicalFile().equals(data) && rawFiles.getName().equals("files"), "Unexpected framework files directory");
            files = new File(data, rawFiles.getName());
            UpdateCore.noSymlinks(data, files);
        }
        ActiveProfile profile = new ActiveProfile(packageUser, info.uid, requestedUid, data, files);
        profile.ensureActive();
        return profile;
    }
    void ensureActive() throws Exception {
        UpdateCore.guardUser(currentUser(), packageUser, uid, requestedUid);
        ownedDirectory(data, uid);
        if (files != null) { UpdateCore.noSymlinks(data, files); ownedDirectory(files, uid); }
    }
    File file(String relative) throws Exception {
        ensureActive();
        UpdateCore.require(files != null, "Private files were not requested");
        File result = new File(files, relative);
        UpdateCore.noSymlinks(files, result);
        StructStat stat = Os.lstat(result.getPath());
        UpdateCore.require(OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == uid, "Private file ownership/type mismatch");
        return result;
    }
}
