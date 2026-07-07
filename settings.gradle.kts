pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "andvari"

include(":core")
include(":server")
include(":app-android")
include(":app-desktop")
include(":tools:vector-gen")
include(":tools:recovery-cli")
include(":tools:backup-cli")
