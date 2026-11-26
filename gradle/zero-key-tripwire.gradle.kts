// The tripwire for keys used after a lock, on a module's JVM test tasks.
//
// The module adds core/src/jvmTripwire (kotlin + resources) to its TEST source set, so the tripwire is on the test class
// path and never in what ships; the shipped seam (core's ZeroKeyWatch) finds it there. This script points it at a record
// file per task and fails the task at its end when the record holds a line that is not marked expected: a seal, open,
// signature, key pair, derivation or MAC under an all-zero key that reached the provider, or a refusal of the floor
// that no test asked for. Expected lines (the floor's and the tripwire's own tests) are counted and reported.
//
// A module may name the tasks to watch in `extra["zeroKeyTripwireTasks"]` (a list of task names) before applying this;
// otherwise every Test task of the module is watched.

@Suppress("UNCHECKED_CAST")
val watchedNames = (extra.properties["zeroKeyTripwireTasks"] as? List<String>)?.toSet()

tasks.withType<Test>().matching { watchedNames == null || it.name in watchedNames }.configureEach {
    val record = layout.buildDirectory.file("zero-key-tripwire/$name.txt").get().asFile
    systemProperty("andvari.test.zeroKeyTripwire", record.absolutePath)
    doFirst {
        record.parentFile.mkdirs()
        record.delete()
    }
    doLast {
        val lines = if (record.exists()) record.readLines().filter { it.isNotBlank() } else emptyList()
        val (expected, found) = lines.partition { it.startsWith("expected ") }
        logger.lifecycle("$path: zero-key tripwire ${if (record.exists()) "on" else "never reached (no crypto provider was made)"}, ${expected.size} expected line(s), ${found.size} other(s)")
        if (found.isNotEmpty()) {
            throw GradleException(
                "Keys after a lock: ${found.size} zero-key operation(s) or floor refusal(s) no test asked for. " +
                    "First: ${found.first()} (all in $record)",
            )
        }
    }
}
