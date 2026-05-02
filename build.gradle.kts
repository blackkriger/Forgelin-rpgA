import java.io.ByteArrayOutputStream
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.Type
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode

plugins {
    id("com.gtnewhorizons.gtnhconvention")
    id("org.jetbrains.kotlin.jvm")
}

val shadowSources = configurations.getByName("shadowSources")
tasks.sourcesJar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(shadowSources.map { zipTree(it) })
}

fun primitiveBoxing(prim: Char): Pair<String, String>? = when (prim) {
    'B' -> "java/lang/Byte" to "(B)Ljava/lang/Byte;"
    'C' -> "java/lang/Character" to "(C)Ljava/lang/Character;"
    'D' -> "java/lang/Double" to "(D)Ljava/lang/Double;"
    'F' -> "java/lang/Float" to "(F)Ljava/lang/Float;"
    'I' -> "java/lang/Integer" to "(I)Ljava/lang/Integer;"
    'J' -> "java/lang/Long" to "(J)Ljava/lang/Long;"
    'S' -> "java/lang/Short" to "(S)Ljava/lang/Short;"
    'Z' -> "java/lang/Boolean" to "(Z)Ljava/lang/Boolean;"
    else -> null
}

fun extractReturnType(desc: String): String {
    val p = desc.lastIndexOf(')')
    return desc.substring(p + 1)
}

fun removeLastObjectParam(desc: String): String {
    val p = desc.lastIndexOf(')')
    var params = desc.substring(1, p)
    val ret = desc.substring(p + 1)
    if (params.endsWith("Ljava/lang/Object;")) {
        params = params.substring(0, params.length - "Ljava/lang/Object;".length)
    }
    return "(" + params + ")" + ret
}

fun widenKotlinAccess(input: File) {
    val tmp = File(input.parentFile, input.name + ".rpgA.tmp")
    var widenedClasses = 0
    var widenedMethods = 0
    var boxBridges = 0
    var defaultBridges = 0
    JarFile(input).use { jar ->
        JarOutputStream(tmp.outputStream()).use { out ->
            val entries = jar.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                val bytes = jar.getInputStream(e).use { it.readBytes() }
                val name = e.name
                val outBytes = if (name.startsWith("kotlin/") && name.endsWith(".class")) {
                    val cr = ClassReader(bytes)
                    val cn = ClassNode()
                    cr.accept(cn, 0)
                    var classChanged = false
                    val existingSigs = cn.methods.map { (it as MethodNode).name + (it as MethodNode).desc }.toHashSet()
                    val toAddDefaults = mutableListOf<MethodNode>()
                    for (m in cn.methods) {
                        val mn = m as MethodNode
                        if (mn.name == "<init>" || mn.name == "<clinit>") continue
                        if ((mn.access and 8) != 0 && (mn.access and 1) == 0) {
                            mn.access = (mn.access and (2 or 4).inv()) or 1
                            widenedMethods++
                            classChanged = true
                        }
                        if (mn.name.endsWith("\$default") && (mn.access and 8) != 0) {
                            val ret = extractReturnType(mn.desc)
                            if (mn.desc.endsWith("Ljava/lang/Object;)" + ret)) {
                                val bridgeDesc = removeLastObjectParam(mn.desc)
                                if (!existingSigs.contains(mn.name + bridgeDesc)) {
                                    val args = Type.getArgumentTypes(bridgeDesc)
                                    val retType = Type.getReturnType(bridgeDesc)
                                    val bridge = MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, mn.name, bridgeDesc, null, null)
                                    val il = InsnList()
                                    var slot = 0
                                    for (a in args) {
                                        il.add(VarInsnNode(a.getOpcode(Opcodes.ILOAD), slot))
                                        slot += a.size
                                    }
                                    il.add(InsnNode(Opcodes.ACONST_NULL))
                                    il.add(MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, mn.name, mn.desc, false))
                                    il.add(InsnNode(retType.getOpcode(Opcodes.IRETURN)))
                                    bridge.instructions = il
                                    toAddDefaults.add(bridge)
                                }
                            }
                        }
                    }
                    if (toAddDefaults.isNotEmpty()) {
                        cn.methods.addAll(toAddDefaults)
                        defaultBridges += toAddDefaults.size
                        classChanged = true
                    }
                    if (name.startsWith("kotlin/jvm/internal/") && name.endsWith("CompanionObject.class")) {
                        val existing = cn.methods.map { (it as MethodNode).name + (it as MethodNode).desc }.toHashSet()
                        val toAdd = mutableListOf<MethodNode>()
                        for (f in cn.fields ?: emptyList<Any>()) {
                            val fn = f as FieldNode
                            if ((fn.access and 8) == 0) continue
                            if (fn.desc == null || fn.desc.length != 1) continue
                            val box = primitiveBoxing(fn.desc[0]) ?: continue
                            val getter = "get" + fn.name + "()Ljava/lang/Object;"
                            if (existing.contains(getter)) continue
                            val mn = MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "get" + fn.name, "()Ljava/lang/Object;", null, null)
                            val il = InsnList()
                            il.add(FieldInsnNode(Opcodes.GETSTATIC, cn.name, fn.name, fn.desc))
                            il.add(MethodInsnNode(Opcodes.INVOKESTATIC, box.first, "valueOf", box.second, false))
                            il.add(InsnNode(Opcodes.ARETURN))
                            mn.instructions = il
                            toAdd.add(mn)
                        }
                        if (toAdd.isNotEmpty()) {
                            cn.methods.addAll(toAdd)
                            boxBridges += toAdd.size
                            classChanged = true
                        }
                    }
                    if (classChanged) widenedClasses++
                    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
                    cn.accept(cw)
                    cw.toByteArray()
                } else {
                    bytes
                }
                val ne = JarEntry(name)
                ne.time = e.time
                out.putNextEntry(ne)
                out.write(outBytes)
                out.closeEntry()
            }
        }
    }
    if (input.delete()) {
        tmp.renameTo(input)
    }
    println("[widenKotlinAccess] " + input.name + ": classes=" + widenedClasses + " widened=" + widenedMethods + " boxBridges=" + boxBridges + " defaultBridges=" + defaultBridges)
}

tasks.register("widenShadedKotlinAccess") {
    doLast {
        val libs = layout.buildDirectory.dir("libs").get().asFile
        if (libs.isDirectory) {
            libs.listFiles { f -> f.isFile && f.name.endsWith(".jar") && !f.name.contains("-sources") && !f.name.contains("-dev") }
                ?.forEach { widenKotlinAccess(it) }
        }
    }
}

tasks.named("assemble") {
    finalizedBy("widenShadedKotlinAccess")
}
