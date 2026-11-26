package io.silencelen.andvari.server

import java.sql.Connection

/**
 * The start-up step that brings a database carrying the current marker ([Db.BASELINE]) up to [Db.SCHEMA]
 * for what the baseline gained after the database was made (the rule at [Db.SCHEMA], spec 02 §5.1).
 *
 * It looks before it adds, so it is safe on every start, and it runs inside the start-up's own transaction:
 *  - a baseline table the database lacks is created, with its indexes;
 *  - a baseline column a table lacks is added with `ALTER TABLE … ADD COLUMN`, when SQLite can add it (it is
 *    nullable, or NOT NULL with a default; never a key, UNIQUE, or a NOT NULL reference);
 *  - a table one of whose column definitions or table constraints differs from the baseline's (a NOT NULL
 *    dropped, a CHECK widened) is rebuilt from the baseline's definition, its rows copied, when no other table
 *    references it;
 *  - a table that still has a column the baseline retired ([Db.RETIRED_COLUMNS]) is rebuilt the same way,
 *    which drops that column, when no other table references it;
 *  - an index the baseline names that the database lacks is created, and one defined differently is dropped
 *    and created as the baseline defines it.
 * Anything else — a column it cannot add (NOT NULL without a default), a column the baseline no longer has and
 * did not retire, a
 * changed table that others reference — refuses the start with [IncompatibleDatabase] and changes nothing.
 * After the step every table of the baseline has exactly the baseline's columns, and every index it names.
 *
 * The comparison is by each column's definition text as the database stores it (SQLite keeps the CREATE text
 * as written, and appends an added column's definition as written), whitespace collapsed.
 */
internal object BaselineCatchUp {
    /** One table of a CREATE TABLE text: its columns' definitions by name, and its table constraints. */
    class TableDef(val name: String, val ddl: String, val columns: LinkedHashMap<String, String>, val constraints: Set<String>)

    private val CREATE_TABLE = Regex("""^\s*CREATE TABLE\s+"?(\w+)"?\s*\(""", RegexOption.IGNORE_CASE)
    private val CREATE_INDEX = Regex("""^\s*CREATE (?:UNIQUE )?INDEX\s+"?(\w+)"?\s+ON\s+"?(\w+)"?\s*\(""", RegexOption.IGNORE_CASE)
    private val REFERENCES = Regex("""REFERENCES\s+"?(\w+)"?""", RegexOption.IGNORE_CASE)
    private val CONSTRAINT_WORDS = setOf("PRIMARY", "CHECK", "UNIQUE", "FOREIGN", "CONSTRAINT")

    /** The baseline's tables, in [Db.SCHEMA] order. */
    val baselineTables: List<TableDef> by lazy { tablesOf(Db.SCHEMA) }

    /** The baseline's CREATE INDEX statements by the table they index. */
    val baselineIndexes: Map<String, List<Pair<String, String>>> by lazy { indexesOf(Db.SCHEMA) }

    /** The tables a schema (a list of statements, as [Db.SCHEMA]) creates, in its order. */
    fun tablesOf(schema: List<String>): List<TableDef> = schema.mapNotNull { ddl -> CREATE_TABLE.find(ddl)?.let { parse(it.groupValues[1], ddl) } }

    /** The CREATE INDEX statements of a schema by the table they index. */
    fun indexesOf(schema: List<String>): Map<String, List<Pair<String, String>>> =
        schema.mapNotNull { ddl -> CREATE_INDEX.find(ddl)?.let { m -> m.groupValues[2] to (m.groupValues[1] to ddl) } }
            .groupBy({ it.first }, { it.second })

    fun parse(name: String, ddl: String): TableDef {
        val body = ddl.substring(ddl.indexOf('(') + 1, ddl.lastIndexOf(')'))
        val columns = LinkedHashMap<String, String>()
        val constraints = LinkedHashSet<String>()
        for (part in splitTopLevel(body)) {
            val def = part.trim().replace(Regex("\\s+"), " ")
            if (def.isEmpty()) continue
            val first = def.substringBefore(' ')
            if (first.uppercase() in CONSTRAINT_WORDS) constraints.add(def) else columns[first.trim('"', '`', '[', ']')] = def
        }
        return TableDef(name, ddl, columns, constraints)
    }

    /** Split at the commas outside parentheses and quotes. */
    private fun splitTopLevel(s: String): List<String> {
        val out = ArrayList<String>()
        var depth = 0
        var quote: Char? = null
        val cur = StringBuilder()
        for (ch in s) {
            when {
                quote != null -> { if (ch == quote) quote = null }
                ch == '\'' || ch == '"' -> quote = ch
                ch == '(' -> depth++
                ch == ')' -> depth--
                ch == ',' && depth == 0 -> { out.add(cur.toString()); cur.clear(); continue }
            }
            cur.append(ch)
        }
        out.add(cur.toString())
        return out
    }

    /** Whether SQLite can add [def] to a table that has rows, with foreign keys on. */
    fun addable(def: String): Boolean {
        val u = " ${def.uppercase()} "
        val notNull = " NOT NULL " in u
        return " PRIMARY KEY " !in u && " UNIQUE " !in u && (!notNull || (" DEFAULT " in u && " REFERENCES " !in u))
    }

    /** The tables of the database as it stands: name to its stored CREATE text. */
    private fun storedTables(c: Connection): Map<String, String> =
        c.queryAll("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'") { it.getString(1) to it.getString(2) }.toMap()

    /**
     * Every difference between the database's tables and the baseline's, one phrase each; empty when they agree. With
     * [schema], the differences from that schema instead (a test asks it with the schema of an earlier build, whose
     * start-up step refuses a database exactly when this list is not empty and names nothing it can add): tables the
     * schema does not name are not looked at, as this step never looks at them.
     */
    fun differences(c: Connection, schema: List<String>? = null): List<String> {
        val tables = schema?.let { tablesOf(it) } ?: baselineTables
        val indexMap = schema?.let { indexesOf(it) } ?: baselineIndexes
        val stored = storedTables(c)
        val out = ArrayList<String>()
        for (t in tables) {
            val sql = stored[t.name]
            if (sql == null) { out.add("table ${t.name} is missing"); continue }
            val have = parse(t.name, sql)
            for ((col, def) in t.columns) {
                val h = have.columns[col]
                if (h == null) out.add("${t.name}.$col is missing") else if (h != def) out.add("${t.name}.$col is '$h', the baseline has '$def'")
            }
            for (col in have.columns.keys - t.columns.keys) out.add("${t.name}.$col is not in the baseline")
            if (have.constraints != t.constraints) out.add("${t.name}'s table constraints differ from the baseline's")
        }
        val indexes = storedIndexes(c)
        for ((name, ddl) in indexMap.values.flatten()) {
            val have = indexes[name]
            if (have == null) out.add("index $name is missing") else if (norm(have) != norm(ddl)) out.add("index $name is '${norm(have)}', the baseline has '${norm(ddl)}'")
        }
        return out
    }

    /**
     * Bring the database up to the baseline inside [c]'s transaction; returns what was added or rebuilt, one phrase
     * each (empty when the database already agreed). Throws [IncompatibleDatabase] for what it cannot bring up.
     */
    fun run(c: Connection): List<String> {
        val stored = storedTables(c)
        val referenced = baselineTables.flatMap { t -> REFERENCES.findAll(t.ddl).map { it.groupValues[1] }.filter { it != t.name }.toList() }.toSet()
        val done = ArrayList<String>()
        for (t in baselineTables) {
            val sql = stored[t.name]
            if (sql == null) {
                c.createStatement().use { st ->
                    st.executeUpdate(t.ddl)
                    for ((_, ddl) in baselineIndexes[t.name].orEmpty()) st.executeUpdate(ddl)
                }
                done.add("created table ${t.name}")
                continue
            }
            val have = parse(t.name, sql)
            val extra = have.columns.keys - t.columns.keys
            val retired = extra.filter { it in Db.RETIRED_COLUMNS[t.name].orEmpty() }
            val unknown = extra - retired.toSet()
            if (unknown.isNotEmpty()) throw olderBuild("${t.name} has ${unknown.joinToString()}, which the baseline no longer has")
            val missing = t.columns.filterKeys { it !in have.columns }
            val unaddable = missing.filterValues { !addable(it) }.keys
            if (unaddable.isNotEmpty()) throw olderBuild("${t.name} lacks ${unaddable.joinToString()}, which this build cannot add to a table that has rows")
            val changed = t.columns.filter { (col, def) -> have.columns[col] != null && have.columns[col] != def }.keys
            val constraintsChanged = have.constraints != t.constraints
            if (changed.isNotEmpty() || constraintsChanged || retired.isNotEmpty()) {
                if (t.name in referenced) {
                    throw olderBuild("${t.name} has changed (${(changed + retired).joinToString()}) and other tables refer to it")
                }
                // The rebuild copies only the baseline's columns, so a retired column is dropped with it.
                rebuild(c, t, have)
                val what = listOfNotNull(
                    changed.takeIf { it.isNotEmpty() }?.let { "its changed ${it.joinToString()}" + if (constraintsChanged) ", table constraints" else "" }
                        ?: "its changed table constraints".takeIf { constraintsChanged },
                    retired.takeIf { it.isNotEmpty() }?.let { "dropping the retired ${it.joinToString()}" },
                    missing.keys.takeIf { it.isNotEmpty() }?.let { "adding ${it.joinToString()}" },
                )
                done.add("rebuilt ${t.name}: ${what.joinToString("; ")}")
                continue
            }
            for ((col, def) in missing) {
                c.createStatement().use { it.executeUpdate("ALTER TABLE ${t.name} ADD COLUMN $def") }
                done.add("added ${t.name}.$col")
            }
        }
        // Every index the baseline names, as the baseline defines it (the tables above are now the baseline's).
        val indexes = storedIndexes(c)
        for ((name, ddl) in baselineIndexes.values.flatten()) {
            val have = indexes[name]
            if (have == null) {
                c.createStatement().use { it.executeUpdate(ddl) }
                done.add("created index $name")
            } else if (norm(have) != norm(ddl)) {
                c.createStatement().use { st -> st.executeUpdate("DROP INDEX $name"); st.executeUpdate(ddl) }
                done.add("rebuilt index $name")
            }
        }
        val left = differences(c)
        if (left.isNotEmpty()) throw olderBuild(left.joinToString("; "))
        return done
    }

    private fun norm(sql: String) = sql.trim().replace(Regex("\\s+"), " ")

    /** The database's own indexes (not SQLite's automatic ones): name to its stored CREATE text. */
    private fun storedIndexes(c: Connection): Map<String, String> =
        c.queryAll("SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL") { it.getString(1) to it.getString(2) }.toMap()

    /** Rebuild [t] from the baseline's definition: create it beside the old one, copy the common columns, swap, re-index. */
    private fun rebuild(c: Connection, t: TableDef, have: TableDef) {
        val tmp = "${t.name}__baseline"
        val cols = t.columns.keys.filter { it in have.columns }.joinToString(",")
        c.createStatement().use { st ->
            st.executeUpdate(CREATE_TABLE.replaceFirst(t.ddl, "CREATE TABLE $tmp("))
            try {
                st.executeUpdate("INSERT INTO $tmp($cols) SELECT $cols FROM ${t.name}")
            } catch (e: java.sql.SQLException) {
                // A row the baseline's definition does not admit: nothing is changed (the start-up transaction rolls back).
                throw olderBuild("the rows of ${t.name} do not fit the baseline's definition (${e.message})")
            }
            st.executeUpdate("DROP TABLE ${t.name}")
            st.executeUpdate("ALTER TABLE $tmp RENAME TO ${t.name}")
            for ((_, ddl) in baselineIndexes[t.name].orEmpty()) st.executeUpdate(ddl)
        }
    }

    fun olderBuild(what: String) = IncompatibleDatabase(Db.olderBuildMessage(what))
}
