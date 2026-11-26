package io.silencelen.andvari.cli

import java.io.DataInputStream
import java.io.File
import java.util.zip.ZipFile

/** The tool's shipped classes, read as class files: every class, field and method each one references. */
object ShippedClasses {
    data class Ref(val owner: String, val name: String, val descriptor: String)

    private fun refs(f: String, bytes: ByteArray): List<Ref> = DataInputStream(bytes.inputStream()).use { d ->
        require(d.readInt() == 0xCAFEBABE.toInt()) { "$f is not a class file" }
        d.readUnsignedShort(); d.readUnsignedShort()
        val n = d.readUnsignedShort()
        val utf = HashMap<Int, String>()
        val cls = HashMap<Int, Int>()
        val nat = HashMap<Int, Pair<Int, Int>>()
        val members = ArrayList<Pair<Int, Int>>()
        var i = 1
        while (i < n) {
            when (val tag = d.readUnsignedByte()) {
                1 -> utf[i] = d.readUTF()
                3, 4 -> d.readInt()
                5, 6 -> { d.readLong(); i++ }
                7 -> cls[i] = d.readUnsignedShort()
                8, 16, 19, 20 -> d.readUnsignedShort()
                9, 10, 11 -> members += d.readUnsignedShort() to d.readUnsignedShort()
                12 -> nat[i] = d.readUnsignedShort() to d.readUnsignedShort()
                15 -> { d.readUnsignedByte(); d.readUnsignedShort() }
                17, 18 -> { d.readUnsignedShort(); d.readUnsignedShort() }
                else -> error("$f: constant tag $tag")
            }
            i++
        }
        members.map { (c, t) -> val (nm, ds) = nat.getValue(t); Ref(utf.getValue(cls.getValue(c)), utf.getValue(nm), utf.getValue(ds)) } +
            cls.values.map { Ref(utf.getValue(it), "", "") }
    }

    /** Class file path (as `io/silencelen/andvari/cli/Host.class`) to its references. */
    val classes: Map<String, List<Ref>> by lazy {
        val root = File(Host::class.java.protectionDomain.codeSource.location.toURI())
        if (root.isDirectory) {
            root.walk().filter { it.isFile && it.name.endsWith(".class") }.associate { it.relativeTo(root).path to refs(it.path, it.readBytes()) }
        } else {
            ZipFile(root).use { z ->
                z.entries().asSequence().filter { it.name.endsWith(".class") }.associate { e -> e.name to refs(e.name, z.getInputStream(e).use { it.readBytes() }) }
            }
        }
    }

    /** The outer class names (as `io/silencelen/andvari/cli/Host`) whose files reference something [pick] accepts, with what. */
    fun users(pick: (Ref) -> Boolean): Map<String, List<Ref>> =
        classes.flatMap { (file, rs) -> rs.filter(pick).map { file.substringBefore('$').removeSuffix(".class") to it } }.groupBy({ it.first }, { it.second })
}
