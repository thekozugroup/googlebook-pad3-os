// SPDX-License-Identifier: Apache-2.0
// Compile-only SDK supplement. These classes must never enter the APK.
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.jetbrains.org.objectweb.asm.*;

public final class CompileApi implements Opcodes {
    public static void main(String[] args) throws Exception {
        Map<String, List<String[]>> members = new TreeMap<>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] v = line.split("\\s+");
            members.computeIfAbsent(v[0], k -> new ArrayList<>()).add(v);
        }
        try (ZipFile sdk = new ZipFile(args[0]);
             ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(Path.of(args[2])))) {
            Set<String> written = new HashSet<>();
            for (var entry : members.entrySet()) {
                String name = entry.getKey();
                ClassWriter w = new ClassWriter(0);
                ZipEntry old = sdk.getEntry(name + ".class");
                if (old != null) {
                    new ClassReader(sdk.getInputStream(old).readAllBytes()).accept(w, 0);
                } else {
                    w.visit(V1_8, ACC_PUBLIC | ACC_ABSTRACT | ACC_SUPER, name, null, "java/lang/Object", null);
                    MethodVisitor init = w.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
                    init.visitCode(); init.visitVarInsn(ALOAD, 0);
                    init.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                    init.visitInsn(RETURN); init.visitMaxs(1, 1); init.visitEnd();
                }
                if (name.startsWith("android/os/UEventObserver")) {
                    w.visitInnerClass("android/os/UEventObserver$UEvent", "android/os/UEventObserver", "UEvent", ACC_PUBLIC | ACC_STATIC);
                }
                for (String[] v : entry.getValue()) {
                    int access = Integer.parseInt(v[3]);
                    if (v[1].equals("FIELD")) {
                        Object value = v[4].equals("I") ? Integer.valueOf(v[5]) : v[5];
                        w.visitField(access, v[2], v[4], null, value).visitEnd();
                    } else {
                        w.visitMethod(access, v[1], v[2], null, null).visitEnd();
                    }
                }
                w.visitEnd();
                ZipEntry z = new ZipEntry(name + ".class"); z.setTime(1230768000000L);
                out.putNextEntry(z); out.write(w.toByteArray()); out.closeEntry();
                written.add(z.getName());
            }
            // Kotlin resolves a patched outer class's nested types from the same archive.
            for (var entries = sdk.entries(); entries.hasMoreElements();) {
                ZipEntry entry = entries.nextElement();
                int dollar = entry.getName().indexOf('$');
                if (dollar < 0 || !entry.getName().endsWith(".class") ||
                    !members.containsKey(entry.getName().substring(0, dollar)) || written.contains(entry.getName())) continue;
                ZipEntry z = new ZipEntry(entry.getName()); z.setTime(1230768000000L);
                out.putNextEntry(z); out.write(sdk.getInputStream(entry).readAllBytes()); out.closeEntry();
            }
        }
    }
}
