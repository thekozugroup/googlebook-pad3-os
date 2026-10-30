import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableField;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Semantic instruction insertion; the Python entrypoint guards the exact original input. */
public final class GraftClient {
    private static final String MANAGER = "Lvendor/google/libraries/desktop/serviceability/ServiceabilityManager;";
    private static final String HELPER = "Lvendor/google/libraries/desktop/serviceability/TaskManagerCompat;";
    private static final String NATIVE_STATS = "Lvendor/google/libraries/desktop/serviceability/NativeProcStats;";
    private static final String CONTEXT = "Landroid/content/Context;";
    private static final String MODE = "mTaskManagerCompat";
    private static final ImmutableFieldReference MODE_FIELD = new ImmutableFieldReference(MANAGER, MODE, "Z");
    private static final ImmutableFieldReference CONTEXT_FIELD = new ImmutableFieldReference(MANAGER, "mContext", CONTEXT);
    private static final Set<String> TARGETS = new HashSet<>(Arrays.asList(
            "<init>(" + CONTEXT + ")V",
            "fetchCpuUsageInfo()" + MANAGER.substring(0, MANAGER.length() - 1) + "$CpuUsageInfo;",
            "fetchCpuUsageInfoWithProcessUsage([I)" + MANAGER.substring(0, MANAGER.length() - 1) + "$CpuUsageInfoWithProcessUsage;",
            "fetchPhysicalCpusInfo()Ljava/util/List;", "getProcessMemoryUsage([I)Ljava/util/List;",
            "stopLongRunningTest(Ljava/lang/String;)V"));

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalArgumentException(message);
    }

    private static String signature(MethodReference method) {
        StringBuilder out = new StringBuilder(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) out.append(type);
        return out.append(')').append(method.getReturnType()).toString();
    }

    private static BuilderInstruction35c call(String name, List<String> arguments, String result,
            int count, int first, int second) {
        return new BuilderInstruction35c(Opcode.INVOKE_STATIC, count, first, second, 0, 0, 0,
                new ImmutableMethodReference(HELPER, name, arguments, result));
    }

    private static Method graft(Method original) {
        MutableMethodImplementation code = new MutableMethodImplementation(original.getImplementation());
        int parameters = original.getParameters().size() + 1;
        int self = code.getRegisterCount() - parameters;
        require(self >= (original.getName().equals("stopLongRunningTest") ? 1 : 2),
                "dead entry temporaries required");
        List<BuilderInstruction> prefix = new ArrayList<>();
        int insertion = 0;
        if (original.getName().equals("<init>")) {
            require(code.getRegisterCount() == 6 && self == 4, "constructor register drift");
            for (int i = 0; i < code.getInstructions().size(); i++) {
                Instruction instruction = code.getInstructions().get(i);
                if (instruction.getOpcode() == Opcode.IPUT_OBJECT
                        && ((ReferenceInstruction) instruction).getReference().equals(CONTEXT_FIELD)) {
                    require(insertion == 0, "repeated context assignment");
                    TwoRegisterInstruction store = (TwoRegisterInstruction) instruction;
                    require(store.getRegisterA() == self + 1 && store.getRegisterB() == self,
                            "context register drift");
                    insertion = i + 1;
                }
            }
            require(insertion > 0, "constructor context assignment missing");
            // v0 is dead here: the original next instruction overwrites it from p0.
            Instruction next = code.getInstructions().get(insertion);
            require(next.getOpcode() == Opcode.IGET_OBJECT
                    && ((TwoRegisterInstruction) next).getRegisterA() == 0
                    && ((TwoRegisterInstruction) next).getRegisterB() == self,
                    "constructor continuation/liveness drift");
            Label continuation = code.newLabelForIndex(insertion);
            prefix.add(call("shouldUse", Collections.singletonList(CONTEXT), "Z", 1, self + 1, 0));
            prefix.add(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            prefix.add(new BuilderInstruction22c(Opcode.IPUT_BOOLEAN, 0, self, MODE_FIELD));
            prefix.add(new BuilderInstruction21t(Opcode.IF_EQZ, 0, continuation));
            prefix.add(new BuilderInstruction10x(Opcode.RETURN_VOID));
        } else {
            Label continuation = code.newLabelForIndex(0);
            prefix.add(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 0, self));
            prefix.add(new BuilderInstruction22c(Opcode.IGET_BOOLEAN, 0, 0, MODE_FIELD));
            prefix.add(new BuilderInstruction21t(Opcode.IF_EQZ, 0, continuation));
            if (original.getName().equals("stopLongRunningTest")) {
                // No local routine can create a token; cancellation is idempotent.
                prefix.add(new BuilderInstruction10x(Opcode.RETURN_VOID));
            } else {
                switch (original.getName()) {
                    case "fetchCpuUsageInfo":
                        prefix.add(call("cpu", Collections.emptyList(), original.getReturnType(), 0, 0, 0));
                        break;
                    case "fetchPhysicalCpusInfo":
                        prefix.add(call("physicalCpus", Collections.emptyList(), original.getReturnType(), 0, 0, 0));
                        break;
                    case "fetchCpuUsageInfoWithProcessUsage":
                        prefix.add(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 0, self));
                        prefix.add(new BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 0, CONTEXT_FIELD));
                        prefix.add(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 1, self + 1));
                        prefix.add(call("cpuWithProcesses", Arrays.asList(CONTEXT, "[I"), original.getReturnType(), 2, 0, 1));
                        break;
                    case "getProcessMemoryUsage":
                        prefix.add(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 0, self));
                        prefix.add(new BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 0, CONTEXT_FIELD));
                        prefix.add(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 1, self + 1));
                        prefix.add(call("memory", Arrays.asList(CONTEXT, "[I"), original.getReturnType(), 2, 0, 1));
                        break;
                    default: throw new IllegalArgumentException("unexpected target");
                }
                prefix.add(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
                prefix.add(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            }
        }
        for (BuilderInstruction instruction : prefix) code.addInstruction(insertion++, instruction);
        return new ImmutableMethod(original.getDefiningClass(), original.getName(), original.getParameters(),
                original.getReturnType(), original.getAccessFlags(), original.getAnnotations(),
                original.getHiddenApiRestrictions(), code);
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 3, "usage: GraftClient original.dex helper.dex output.dex");
        DexFile original = DexFileFactory.loadDexFile(args[0], null);
        DexFile helper = DexFileFactory.loadDexFile(args[1], null);
        Set<String> clientMethods = new HashSet<>();
        Set<String> clientFields = new HashSet<>();
        for (ClassDef cls : original.getClasses()) {
            for (Method method : cls.getMethods()) {
                if ((method.getAccessFlags() & 1) != 0) {
                    clientMethods.add(cls.getType() + "->" + signature(method));
                }
            }
            for (Field field : cls.getFields()) {
                if ((field.getAccessFlags() & 1) != 0) {
                    clientFields.add(cls.getType() + "->" + field.getName() + ":" + field.getType());
                }
            }
        }
        Set<String> checkedReferences = new HashSet<>();
        for (ClassDef cls : helper.getClasses()) {
            for (Method method : cls.getMethods()) {
                if (method.getImplementation() == null) continue;
                for (Instruction instruction : method.getImplementation().getInstructions()) {
                    if (!(instruction instanceof ReferenceInstruction)) continue;
                    Reference ref = ((ReferenceInstruction) instruction).getReference();
                    String owner = null;
                    String key = null;
                    Set<String> available = null;
                    if (ref instanceof MethodReference) {
                        MethodReference target = (MethodReference) ref;
                        owner = target.getDefiningClass();
                        key = owner + "->" + signature(target);
                        available = clientMethods;
                    } else if (ref instanceof FieldReference) {
                        FieldReference target = (FieldReference) ref;
                        owner = target.getDefiningClass();
                        key = owner + "->" + target.getName() + ":" + target.getType();
                        available = clientFields;
                    }
                    if (owner != null && (owner.equals(MANAGER)
                            || owner.startsWith(MANAGER.substring(0, MANAGER.length() - 1) + "$"))) {
                        require(available.contains(key), "helper client reference does not resolve: " + key);
                        checkedReferences.add(key);
                    }
                }
            }
        }
        require(!checkedReferences.isEmpty(), "helper has no original DTO references");
        List<ClassDef> classes = new ArrayList<>();
        Set<String> changed = new HashSet<>();
        int managers = 0;
        for (ClassDef cls : original.getClasses()) {
            require(!cls.getType().equals(NATIVE_STATS) && !cls.getType().equals(HELPER)
                    && !cls.getType().startsWith(HELPER.substring(0, HELPER.length() - 1) + "$"),
                    "already patched input");
            if (!cls.getType().equals(MANAGER)) {
                classes.add(cls);
                continue;
            }
            managers++;
            List<Field> fields = new ArrayList<>();
            for (Field field : cls.getFields()) {
                require(!field.getName().equals(MODE), "mode field already exists");
                fields.add(field);
            }
            fields.add(new ImmutableField(MANAGER, MODE, "Z", 0x1012, null,
                    Collections.emptySet(), Collections.emptySet()));
            List<Method> methods = new ArrayList<>();
            for (Method method : cls.getMethods()) {
                String sig = signature(method);
                if (TARGETS.contains(sig)) {
                    require(changed.add(sig), "duplicate target method");
                    methods.add(graft(method));
                } else {
                    methods.add(method);
                }
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(),
                    cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), fields, methods));
        }
        require(managers == 1 && changed.equals(TARGETS), "exact method target set drift");
        int added = 0;
        boolean found = false;
        for (ClassDef cls : helper.getClasses()) {
            require(cls.getType().equals(NATIVE_STATS) || cls.getType().equals(HELPER)
                    || cls.getType().startsWith(HELPER.substring(0, HELPER.length() - 1) + "$"),
                    "compile-only or unrelated class in helper DEX: " + cls.getType());
            found |= cls.getType().equals(HELPER);
            classes.add(cls);
            added++;
        }
        require(found, "helper missing");
        DexPool.writeTo(args[2], new ImmutableDexFile(original.getOpcodes(), classes));
        System.out.println("{\"grafted_methods\":6,\"original_classes\":" + original.getClasses().size()
                + ",\"helper_classes\":" + added + ",\"validated_client_references\":"
                + checkedReferences.size() + "}");
    }
}
